// SPDX-License-Identifier: GPL-3.0-or-later
import * as docker from "@pulumi/docker";
import * as pulumi from "@pulumi/pulumi";
import {Package} from "./package";

export function image(pkg: Package, name: pulumi.Input<string>, registry: docker.types.input.Registry, opts: pulumi.CustomResourceOptions = {}): docker.Image {
    return new docker.Image("receiver-image", {
        imageName: name,
        build: {builderVersion: docker.BuilderVersion.BuilderBuildKit, context: pkg.directory, platform: "linux/amd64", args: {CONFIG_DIR: "config"}},
        buildOnPreview: false,
        registry,
    }, opts);
}
