#!/usr/bin/env groovy

buildPlugin(useContainerAgent: true,
        configurations: [
                [platform: 'linux', jdk: '11'],
                [platform: 'windows', jdk: '11'],

                // testing the Guava & Guice bumps
                // https://github.com/jenkinsci/jenkins/pull/5707
                // https://github.com/jenkinsci/jenkins/pull/5858
                [ platform: "linux", jdk: "11", jenkins: '2.321', javaLevel: "8" ]
        ])
