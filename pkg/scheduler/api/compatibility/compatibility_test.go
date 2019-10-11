/*
Copyright 2015 The Kubernetes Authors.

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

package compatibility

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/kubernetes/pkg/scheduler"
	_ "k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults"
	schedulerapi "k8s.io/kubernetes/pkg/scheduler/api"
	kubeschedulerconfig "k8s.io/kubernetes/pkg/scheduler/apis/config"
	schedulerconfig "k8s.io/kubernetes/pkg/scheduler/apis/config"
	"k8s.io/kubernetes/pkg/scheduler/core"
	"k8s.io/kubernetes/pkg/scheduler/factory"
	schedulerframework "k8s.io/kubernetes/pkg/scheduler/framework/plugins"
)

func TestCompatibility_v1_Scheduler(t *testing.T) {
	// Add serialized versions of scheduler config that exercise available options to ensure compatibility between releases
	schedulerFiles := map[string]struct {
		JSON             string
		wantPredicates   sets.String
		wantPrioritizers sets.String
		wantExtenders    []schedulerapi.ExtenderConfig
	}{
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.0": {
			JSON: `{
  "kind": "Policy",
  "apiVersion": "v1",
  "predicates": [
    {"name": "MatchNodeSelector"},
    {"name": "PodFitsResources"},
    {"name": "PodFitsPorts"},
    {"name": "NoDiskConflict"},
    {"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
    {"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
  ],"priorities": [
    {"name": "LeastRequestedPriority",   "weight": 1},
    {"name": "ServiceSpreadingPriority", "weight": 2},
    {"name": "TestServiceAntiAffinity",  "weight": 3, "argument": {"serviceAntiAffinity": {"label": "zone"}}},
    {"name": "TestLabelPreference",      "weight": 4, "argument": {"labelPreference": {"label": "bar", "presence":true}}}
  ]
}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsPorts",
				"NoDiskConflict",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"LeastRequestedPriority",
				"ServiceSpreadingPriority",
				"TestServiceAntiAffinity",
				"TestLabelPreference",
			),
		},

		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.1": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsHostPorts"},
			{"name": "PodFitsResources"},
			{"name": "NoDiskConflict"},
			{"name": "HostName"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "TestServiceAntiAffinity",  "weight": 3, "argument": {"serviceAntiAffinity": {"label": "zone"}}},
			{"name": "TestLabelPreference",      "weight": 4, "argument": {"labelPreference": {"label": "bar", "presence":true}}}
		  ]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsHostPorts",
				"PodFitsResources",
				"NoDiskConflict",
				"HostName",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"TestServiceAntiAffinity",
				"TestLabelPreference",
			),
		},

		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.2": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "TestServiceAntiAffinity",  "weight": 3, "argument": {"serviceAntiAffinity": {"label": "zone"}}},
			{"name": "TestLabelPreference",      "weight": 4, "argument": {"labelPreference": {"label": "bar", "presence":true}}}
		  ]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"NodeAffinityPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"TestServiceAntiAffinity",
				"TestLabelPreference",
			),
		},

		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.3": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2}
		  ]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
			),
		},

		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.4": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2}
		  ]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
			),
		},
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.7": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"BindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.7 was missing json tags on the BindVerb field and required "BindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
			}},
		},
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.8": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.8 became case-insensitive and tolerated "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
			}},
		},
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.9": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.9 was case-insensitive and tolerated "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
			}},
		},

		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.10": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodePIDPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true,
			"managedResources": [{"name":"example.com/foo","ignoredByScheduler":true}],
			"ignorable":true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodePIDPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.10 was case-insensitive and tolerated "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
				ManagedResources: []schedulerapi.ExtenderManagedResource{{Name: v1.ResourceName("example.com/foo"), IgnoredByScheduler: true}},
				Ignorable:        true,
			}},
		},
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.11": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodePIDPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2},
			{
				"name": "RequestedToCapacityRatioPriority",
				"weight": 2,
				"argument": {
				"requestedToCapacityRatioArguments": {
					"shape": [
						{"utilization": 0,  "score": 0},
						{"utilization": 50, "score": 7}
					]
				}
			}}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true,
			"managedResources": [{"name":"example.com/foo","ignoredByScheduler":true}],
			"ignorable":true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodePIDPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
				"RequestedToCapacityRatioPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.11 restored case-sensitivity, but allowed either "BindVerb" or "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
				ManagedResources: []schedulerapi.ExtenderManagedResource{{Name: v1.ResourceName("example.com/foo"), IgnoredByScheduler: true}},
				Ignorable:        true,
			}},
		},
		// Do not change this JSON after the corresponding release has been tagged.
		// A failure indicates backwards compatibility with the specified release was broken.
		"1.12": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodePIDPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MaxCSIVolumeCountPred"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2},
			{
				"name": "RequestedToCapacityRatioPriority",
				"weight": 2,
				"argument": {
				"requestedToCapacityRatioArguments": {
					"shape": [
						{"utilization": 0,  "score": 0},
						{"utilization": 50, "score": 7}
					]
				}
			}}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true,
			"managedResources": [{"name":"example.com/foo","ignoredByScheduler":true}],
			"ignorable":true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodePIDPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MaxCSIVolumeCountPred",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
				"RequestedToCapacityRatioPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.11 restored case-sensitivity, but allowed either "BindVerb" or "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
				ManagedResources: []schedulerapi.ExtenderManagedResource{{Name: v1.ResourceName("example.com/foo"), IgnoredByScheduler: true}},
				Ignorable:        true,
			}},
		},
		"1.14": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodePIDPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MaxCSIVolumeCountPred"},
                        {"name": "MaxCinderVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2},
			{
				"name": "RequestedToCapacityRatioPriority",
				"weight": 2,
				"argument": {
				"requestedToCapacityRatioArguments": {
					"shape": [
						{"utilization": 0,  "score": 0},
						{"utilization": 50, "score": 7}
					]
				}
			}}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true,
			"managedResources": [{"name":"example.com/foo","ignoredByScheduler":true}],
			"ignorable":true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodePIDPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MaxCSIVolumeCountPred",
				"MaxCinderVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
				"RequestedToCapacityRatioPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.11 restored case-sensitivity, but allowed either "BindVerb" or "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
				ManagedResources: []schedulerapi.ExtenderManagedResource{{Name: v1.ResourceName("example.com/foo"), IgnoredByScheduler: true}},
				Ignorable:        true,
			}},
		},
		"1.16": {
			JSON: `{
		  "kind": "Policy",
		  "apiVersion": "v1",
		  "predicates": [
			{"name": "MatchNodeSelector"},
			{"name": "PodFitsResources"},
			{"name": "PodFitsHostPorts"},
			{"name": "HostName"},
			{"name": "NoDiskConflict"},
			{"name": "NoVolumeZoneConflict"},
			{"name": "PodToleratesNodeTaints"},
			{"name": "CheckNodeMemoryPressure"},
			{"name": "CheckNodeDiskPressure"},
			{"name": "CheckNodePIDPressure"},
			{"name": "CheckNodeCondition"},
			{"name": "MaxEBSVolumeCount"},
			{"name": "MaxGCEPDVolumeCount"},
			{"name": "MaxAzureDiskVolumeCount"},
			{"name": "MaxCSIVolumeCountPred"},
                        {"name": "MaxCinderVolumeCount"},
			{"name": "MatchInterPodAffinity"},
			{"name": "GeneralPredicates"},
			{"name": "CheckVolumeBinding"},
			{"name": "TestServiceAffinity", "argument": {"serviceAffinity" : {"labels" : ["region"]}}},
			{"name": "TestLabelsPresence",  "argument": {"labelsPresence"  : {"labels" : ["foo"], "presence":true}}}
		  ],"priorities": [
			{"name": "EqualPriority",   "weight": 2},
			{"name": "ImageLocalityPriority",   "weight": 2},
			{"name": "LeastRequestedPriority",   "weight": 2},
			{"name": "BalancedResourceAllocation",   "weight": 2},
			{"name": "SelectorSpreadPriority",   "weight": 2},
			{"name": "NodePreferAvoidPodsPriority",   "weight": 2},
			{"name": "NodeAffinityPriority",   "weight": 2},
			{"name": "TaintTolerationPriority",   "weight": 2},
			{"name": "InterPodAffinityPriority",   "weight": 2},
			{"name": "MostRequestedPriority",   "weight": 2},
			{
				"name": "RequestedToCapacityRatioPriority",
				"weight": 2,
				"argument": {
				"requestedToCapacityRatioArguments": {
					"shape": [
						{"utilization": 0,  "score": 0},
						{"utilization": 50, "score": 7}
					],
					"resources": [
						{"name": "intel.com/foo", "weight": 3},
						{"name": "intel.com/bar", "weight": 5}
					]
				}
			}}
		  ],"extenders": [{
			"urlPrefix":        "/prefix",
			"filterVerb":       "filter",
			"prioritizeVerb":   "prioritize",
			"weight":           1,
			"bindVerb":         "bind",
			"enableHttps":      true,
			"tlsConfig":        {"Insecure":true},
			"httpTimeout":      1,
			"nodeCacheCapable": true,
			"managedResources": [{"name":"example.com/foo","ignoredByScheduler":true}],
			"ignorable":true
		  }]
		}`,
			wantPredicates: sets.NewString(
				"MatchNodeSelector",
				"PodFitsResources",
				"PodFitsHostPorts",
				"HostName",
				"NoDiskConflict",
				"NoVolumeZoneConflict",
				"PodToleratesNodeTaints",
				"CheckNodeMemoryPressure",
				"CheckNodeDiskPressure",
				"CheckNodePIDPressure",
				"CheckNodeCondition",
				"MaxEBSVolumeCount",
				"MaxGCEPDVolumeCount",
				"MaxAzureDiskVolumeCount",
				"MaxCSIVolumeCountPred",
				"MaxCinderVolumeCount",
				"MatchInterPodAffinity",
				"GeneralPredicates",
				"CheckVolumeBinding",
				"TestServiceAffinity",
				"TestLabelsPresence",
			),
			wantPrioritizers: sets.NewString(
				"EqualPriority",
				"ImageLocalityPriority",
				"LeastRequestedPriority",
				"BalancedResourceAllocation",
				"SelectorSpreadPriority",
				"NodePreferAvoidPodsPriority",
				"NodeAffinityPriority",
				"TaintTolerationPriority",
				"InterPodAffinityPriority",
				"MostRequestedPriority",
				"RequestedToCapacityRatioPriority",
			),
			wantExtenders: []schedulerapi.ExtenderConfig{{
				URLPrefix:        "/prefix",
				FilterVerb:       "filter",
				PrioritizeVerb:   "prioritize",
				Weight:           1,
				BindVerb:         "bind", // 1.11 restored case-sensitivity, but allowed either "BindVerb" or "bindVerb"
				EnableHTTPS:      true,
				TLSConfig:        &schedulerapi.ExtenderTLSConfig{Insecure: true},
				HTTPTimeout:      1,
				NodeCacheCapable: true,
				ManagedResources: []schedulerapi.ExtenderManagedResource{{Name: v1.ResourceName("example.com/foo"), IgnoredByScheduler: true}},
				Ignorable:        true,
			}},
		},
	}
	registeredPredicates := sets.NewString(factory.ListRegisteredFitPredicates()...)
	registeredPriorities := sets.NewString(factory.ListRegisteredPriorityFunctions()...)
	seenPredicates := sets.NewString()
	seenPriorities := sets.NewString()
	mandatoryPredicates := sets.NewString("CheckNodeCondition")

	for v, tc := range schedulerFiles {
		t.Run(v, func(t *testing.T) {
			policyConfigMap := v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceSystem, Name: "scheduler-custom-policy-config"},
				Data:       map[string]string{schedulerconfig.SchedulerPolicyConfigMapKey: tc.JSON},
			}
			client := fake.NewSimpleClientset(&policyConfigMap)
			algorithmSrc := schedulerconfig.SchedulerAlgorithmSource{
				Policy: &schedulerconfig.SchedulerPolicySource{
					ConfigMap: &kubeschedulerconfig.SchedulerPolicyConfigMapSource{
						Namespace: policyConfigMap.Namespace,
						Name:      policyConfigMap.Name,
					},
				},
			}
			informerFactory := informers.NewSharedInformerFactory(client, 0)

			sched, err := scheduler.New(
				client,
				informerFactory.Core().V1().Nodes(),
				informerFactory.Core().V1().Pods(),
				informerFactory.Core().V1().PersistentVolumes(),
				informerFactory.Core().V1().PersistentVolumeClaims(),
				informerFactory.Core().V1().ReplicationControllers(),
				informerFactory.Apps().V1().ReplicaSets(),
				informerFactory.Apps().V1().StatefulSets(),
				informerFactory.Core().V1().Services(),
				informerFactory.Policy().V1beta1().PodDisruptionBudgets(),
				informerFactory.Storage().V1().StorageClasses(),
				informerFactory.Storage().V1beta1().CSINodes(),
				nil,
				algorithmSrc,
				make(chan struct{}),
				schedulerframework.NewDefaultRegistry(),
				nil,
				[]kubeschedulerconfig.PluginConfig{},
			)
			if err != nil {
				t.Fatalf("%s: Error constructing: %v", v, err)
			}
			schedPredicates := sets.NewString()
			for p := range sched.Algorithm.Predicates() {
				schedPredicates.Insert(p)
			}
			wantPredicates := tc.wantPredicates.Union(mandatoryPredicates)
			if !schedPredicates.Equal(wantPredicates) {
				t.Errorf("Got predicates %v, want %v", schedPredicates, wantPredicates)
			}
			schedPrioritizers := sets.NewString()
			for _, p := range sched.Algorithm.Prioritizers() {
				schedPrioritizers.Insert(p.Name)
			}

			if !schedPrioritizers.Equal(tc.wantPrioritizers) {
				t.Errorf("Got prioritizers %v, want %v", schedPrioritizers, tc.wantPrioritizers)
			}
			schedExtenders := sched.Algorithm.Extenders()
			var wantExtenders []*core.HTTPExtender
			for _, e := range tc.wantExtenders {
				extender, err := core.NewHTTPExtender(&e)
				if err != nil {
					t.Errorf("Error transforming extender: %+v", e)
				}
				wantExtenders = append(wantExtenders, extender.(*core.HTTPExtender))
			}
			for i := range schedExtenders {
				if !core.Equal(wantExtenders[i], schedExtenders[i].(*core.HTTPExtender)) {
					t.Errorf("Got extender #%d %+v, want %+v", i, schedExtenders[i], wantExtenders[i])
				}
			}
			seenPredicates = seenPredicates.Union(schedPredicates)
			seenPriorities = seenPriorities.Union(schedPrioritizers)
		})
	}

	if !seenPredicates.HasAll(registeredPredicates.List()...) {
		t.Errorf("Registered predicates are missing from compatibility test (add to test stanza for version currently in development): %#v", registeredPredicates.Difference(seenPredicates).List())
	}
	if !seenPriorities.HasAll(registeredPriorities.List()...) {
		t.Errorf("Registered priorities are missing from compatibility test (add to test stanza for version currently in development): %#v", registeredPriorities.Difference(seenPriorities).List())
	}
}
