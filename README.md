# .NET bindings for RNP

This project provides .NET Core bindings for the [RNP high performance OpenPGP](https://github.com/rnpgp/rnp) library.

## Requirements

.NET Core 3.1

[RNP](https://github.com/rnpgp/rnp)

## Build Instructions

1. Download, build and install shared version of the [RNP OpenPGP library](https://github.com/rnpgp/rnp).

2. Build this project.

    ```
    dotnet build
    ```

## Testing

```
dotnet test
```

## Examples

There are .NET Core C# and VB variants of [RNP's examples](https://github.com/rnpgp/rnp/tree/master/src/examples) under the [examples](examples) and [examples_vb](examples_vb) folders.
