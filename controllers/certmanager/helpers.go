/*
Copyright 2020 Skyscanner Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aws/smithy-go"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// maxEventNote is the longest note an events.k8s.io/v1 Event may carry: the API
// server refuses a longer one, and the recorder drops the refused event.
const maxEventNote = 1024

// eventf records an event on regarding with the formatted note, cut to
// maxEventNote bytes (at a character boundary, ending in "...") so that a long
// message (a requester's long name in a refusal, say) never loses the event.
// The status condition and the log keep the full text.
func eventf(rec events.EventRecorder, regarding runtime.Object, eventtype, reason, action, format string, args ...any) {
	rec.Eventf(regarding, nil, eventtype, reason, action, "%s", eventNote(fmt.Sprintf(format, args...)))
}

// eventNote is note cut to at most maxEventNote bytes.
func eventNote(note string) string {
	if len(note) <= maxEventNote {
		return note
	}
	const ellipsis = "..."
	cut := maxEventNote - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(note[cut]) {
		cut--
	}
	return note[:cut] + ellipsis
}

// stableText is err's text with every AWS operation error in it cut down to the
// operation and its error code, for status conditions. The SDK's own text carries
// a request ID that is new on every call, and the AWS message may vary too:
// written into a condition, either would change the object on every retry, and
// the watch event each change makes would start the next pass at once, past the
// work queue's backoff. Error codes don't vary.
func stableText(err error) string { return awsText(err, false) }

// eventText is stableText with each AWS error's message, for events (which start
// no pass). The log keeps the full error, with its request ID.
func eventText(err error) string { return awsText(err, true) }

func awsText(err error, withMessage bool) string {
	text := err.Error()
	for _, op := range operationErrors(err) {
		short := fmt.Sprintf("%s %s failed (the controller log has the details)", op.Service(), op.Operation())
		var api smithy.APIError
		if errors.As(op.Err, &api) {
			short = fmt.Sprintf("%s %s: %s", op.Service(), op.Operation(), api.ErrorCode())
			if withMessage {
				short += ": " + api.ErrorMessage()
			}
		}
		text = strings.Replace(text, op.Error(), short, 1)
	}
	return text
}

// operationErrors are the outermost AWS operation errors in err's tree (through
// wrapped and joined errors alike).
func operationErrors(err error) []*smithy.OperationError {
	if op, ok := err.(*smithy.OperationError); ok {
		return []*smithy.OperationError{op}
	}
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); inner != nil {
			return operationErrors(inner)
		}
	case interface{ Unwrap() []error }:
		var ops []*smithy.OperationError
		for _, inner := range e.Unwrap() {
			if inner != nil {
				ops = append(ops, operationErrors(inner)...)
			}
		}
		return ops
	}
	return nil
}

// readerOr is reader, or c when reader is nil (a reconciler built without an
// uncached reader, as in unit tests).
func readerOr(reader client.Reader, c client.Client) client.Reader {
	if reader != nil {
		return reader
	}
	return c
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
