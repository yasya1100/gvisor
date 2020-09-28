load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checklocks",
    srcs = ["checklocks.go"],
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_tool_library",
        "@org_golang_x_tools//go/analysis/passes/buildssa:go_tool_library",
        "@org_golang_x_tools//go/ssa:go_tool_library",
    ],
)
