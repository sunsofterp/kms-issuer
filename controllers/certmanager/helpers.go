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

// stableText is err's text with the AWS operation error in it, if any, cut down to
// the operation, the error code and the message. The SDK's own text carries a
// request ID that is new on every call: written into a status condition, it would
// change the object on every retry, and the watch event each change makes would
// start the next pass at once, past the work queue's backoff. Statuses and events
// take this text; the log keeps the full error.
func stableText(err error) string {
	text := err.Error()
	var op *smithy.OperationError
	if !errors.As(err, &op) {
		return text
	}
	short := fmt.Sprintf("%s %s failed (the controller log has the details)", op.Service(), op.Operation())
	var api smithy.APIError
	if errors.As(op.Err, &api) {
		short = fmt.Sprintf("%s %s: %s: %s", op.Service(), op.Operation(), api.ErrorCode(), api.ErrorMessage())
	}
	return strings.Replace(text, op.Error(), short, 1)
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
