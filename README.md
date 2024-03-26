# Kubeseal helper

Simple wrapper to make various kinds of K8S secrets and call `kubeseal` to generate `SealedSecret`.

The password parts of the secret is randomly generated. No intermediate (unencrypted) files on disk.
