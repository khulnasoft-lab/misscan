package misscan.kubernetes.KSV107

import data.k8s
import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV107",
	"avd_id": "AVD-KSV-0107",
	"title": "Evaluate k8s deprecated and removed APIs",
	"short_code": "evaluate-k8s-deprecated-removed-apis",
	"severity": "LOW",
	"description": sprintf("apiVersion '%s' and kind '%s' has been deprecated on: '%s' and planned for removal on:'%s'", [recommend[_].apiVersion, recommend[_].kind, recommend[_].deprecation_version, recommend[_].removed_version]),
	"recommended_actions": sprintf("It recommended to move to the new replacement API:'%s'", [recommend[_].replacement_version]),
	"url": sprintf("%s", [recommend[_].ref]),
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# this is necessary to ensure metadata can still be parsed dynamically when no input is provided
recommend[info] {
	not input.apiVersion
	info := {
		"ref": "",
		"deprecation_version": "",
		"removed_version": "",
		"replacement_version": "",
		"apiVersion": "",
		"kind": "",
	}
}

exists(obj, k) {
	_ = obj[k]
}

pick(k, obj1, obj2) = v {
	v := obj1[k]
}

pick(k, obj1, obj2) = v {
	not exists(obj1, k)
	v := obj2[k]
}

merge(a, b) = c {
	keys := {k | _ = a[k]} | {k | _ = b[k]}
	c := {k: v | k := keys[_]; v := pick(k, b, a)}
}

recommend[info] {
	input
	base := recommendedVersions[input.apiVersion][input.kind]
	extra := {
		"apiVersion": input.apiVersion,
		"kind": input.kind,
	}

	info := merge(base, extra)
}

recommendedVersions := 

deny[res] {
	obj := recommendedVersions[input.apiVersion][input.kind]
	compareVersion(obj)
	msg := sprintf("apiVersion '%s' and kind ‘%s' should be replaced with the new API '%s'\nSee %s", [input.apiVersion, input.kind, recommendedVersions[input.apiVersion][input.kind].replacement_version, recommendedVersions[input.apiVersion][input.kind].ref])
	res := result.new(msg, {"__misscan_metadata": {"startline": 1, "endline": 5}})
}

compareVersion(obj) {
	# deprecated version
	depVer := obj.deprecation_version
	apiDepVer := semanticVersion(depVer)
	resultDep := semver.compare(k8s.version, apiDepVer)

	# removed version
	remVer := obj.removed_version
	apiRemVer := semanticVersion(remVer)
	resultRem := semver.compare(k8s.version, apiRemVer)
	valid(resultDep, resultRem)
}

compareVersion(obj) {
	not k8s
}

# k8sversion == deprecated && k8sversion < removed
valid(resultDep, resultRem) {
	resultDep == 0
	resultRem == -1
}

# k8sversion > deprecated && k8sversion < removed
valid(resultDep, resultRem) {
	resultDep == 1
	resultRem == -1
}

# k8sversion > deprecated && k8sversion > removed
valid(resultDep, resultRem) {
	resultDep == 1
	resultRem == 1
}

# k8sversion > deprecated && k8sversion == removed
valid(resultDep, resultRem) {
	resultDep == 1
	resultRem == 0
}

semanticVersion(version) = apiSemVer {
	cVer := replace(version, "v", "")
	apiSemVer := concat("", [cVer, ".0"])
}
