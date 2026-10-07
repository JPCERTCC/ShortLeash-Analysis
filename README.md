# ShortLeash ConfigExtractor - IDA Plugin

ShortLeash ConfigExtractor is an IDA plugin for extracting configuration data from **ShortLeash** malware samples.

The plugin supports both known ShortLeash samples and identified variants.

### Features

- Extracts configuration data from ShortLeash samples
- Supports both known and variant ShortLeash samples
- Runs directly as an IDA plugin
- Supports multiple executable formats and architectures

### Supported Targets

| Format | Architecture |
| ------ | ------------ |
| PE     | x86-64       |
| ELF    | x86-64       |
| ELF    | ARM32        |

### Pre-built Plugins for Windows

Pre-built Windows plugin binaries are provided for the following IDA versions:

| IDA Version | Plugin File                         |
| ----------- | ----------------------------------- |
| IDA 8.4     | `ShortLeash_ConfigExtractor_84.dll` |
| IDA 9.0     | `ShortLeash_ConfigExtractor_90.dll` |
| IDA 9.1     | `ShortLeash_ConfigExtractor_91.dll` |
| IDA 9.2     | `ShortLeash_ConfigExtractor_92.dll` |
| IDA 9.3     | `ShortLeash_ConfigExtractor_93.dll` |
| IDA 9.4     | `ShortLeash_ConfigExtractor_94.dll` |

Select the DLL corresponding to your IDA version.

### Installation

1. Select the plugin DLL that matches your IDA version.
2. Copy the DLL to the `plugins` directory of your IDA installation.
3. Restart IDA.

Example:

```text
<IDA installation directory>\plugins\ShortLeash_ConfigExtractor_94.dll
```

### Usage

1. Open a ShortLeash sample in IDA.
2. Wait for IDA's initial analysis to complete.
3. Run **ShortLeash ConfigExtractor** from the IDA plugin menu.
4. The plugin identifies and extracts the ShortLeash configuration data.
5. The extracted configuration is displayed in IDA.

### Source Code

The C++ source code for the IDA plugin is available in the repository's `src` directory.

The source code can be used to review the extraction logic or build the plugin for other IDA environments.
