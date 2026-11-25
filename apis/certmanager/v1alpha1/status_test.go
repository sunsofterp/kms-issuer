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

package v1alpha1

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestStatusShouldAddNewConditions(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	oups := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "oups")
	status.SetCondition(&oups)
	g.Expect(status.Conditions[0]).To(Equal(oups))
	g.Expect(len(status.Conditions)).To(Equal(1))
}

func TestShouldReplacePreExistingConditions(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
	status.SetCondition(&empty)
	oups := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "oups")
	status.SetCondition(&oups)
	g.Expect(status.Conditions[0]).To(Equal(oups))
	g.Expect(len(status.Conditions)).To(Equal(1))
}

// should not touch the condition when status, reason and message are all unchanged.
func TestShouldNotUpdateExistingCondition(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	because := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "because")
	status.SetCondition(&because)
	same := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "because")
	same.LastTransitionTime.Time = same.LastTransitionTime.Add(time.Hour)
	status.SetCondition(&same)
	g.Expect(status.Conditions[0]).To(Equal(because))
	g.Expect(len(status.Conditions)).To(Equal(1))
}

// a new message with the same status replaces the message but keeps the transition time.
func TestShouldUpdateTheMessageKeepingTheTransitionTime(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	because := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "because")
	status.SetCondition(&because)
	otherMsg := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonFailed, "othermsg")
	otherMsg.LastTransitionTime.Time = otherMsg.LastTransitionTime.Add(time.Hour)
	status.SetCondition(&otherMsg)
	g.Expect(status.Conditions[0].Message).To(Equal("othermsg"))
	g.Expect(status.Conditions[0].LastTransitionTime).To(Equal(because.LastTransitionTime))
	g.Expect(len(status.Conditions)).To(Equal(1))
}

// GetCondition should return a condition by type
func TestGetConditionShouldReturnByType(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
	status.SetCondition(&empty)
	g.Expect(*status.GetCondition(ConditionReady)).To(Equal(empty))
}

// IsReady should return true when the Ready Condition is true
func TestIsReadyShouldReturnTrue(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	empty := NewCondition(ConditionReady, ConditionTrue, KMSIssuerReasonIssued, "")
	status.SetCondition(&empty)
	g.Expect(status.IsReady()).To(BeTrue())
}

// "IsReady should return false with the Ready Condition is false
func TestIsReadyConditionIsFalse(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	empty := NewCondition(ConditionReady, ConditionFalse, KMSIssuerReasonIssued, "")
	status.SetCondition(&empty)
	g.Expect(status.IsReady()).To(BeFalse())
}

// IsReady should return false with the Ready Condition is not set
func TestIsReadyConditionNotSet(t *testing.T) {
	g := NewWithT(t)
	status := &Status{}
	g.Expect(status.IsReady()).To(BeFalse())
}
