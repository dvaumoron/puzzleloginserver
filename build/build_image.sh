#!/usr/bin/env bash

go install

buildah from --name puzzleloginserver-working-container scratch
buildah copy puzzleloginserver-working-container $HOME/go/bin/puzzleloginserver /bin/puzzleloginserver
buildah config --env SERVICE_PORT=50051 puzzleloginserver-working-container
buildah config --port 50051 puzzleloginserver-working-container
buildah config --entrypoint '["/bin/puzzleloginserver"]' puzzleloginserver-working-container
buildah commit puzzleloginserver-working-container puzzleloginserver
buildah rm puzzleloginserver-working-container

buildah push puzzleloginserver docker-daemon:puzzleloginserver:latest
