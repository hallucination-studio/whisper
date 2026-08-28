# External references

This index is the canonical owner of external source identity, version/date,
locator, and provenance used by Whisper documentation. A citation is evidence
input, not a normative contract, implementation claim, or promotion decision.

Sources were catalogued from the protected architecture at revision
`f83428c31aba285277fc95db4079228b97ecaa62` on 2026-08-27. `Not recorded` means
the protected source did not pin a version or publication/access date; that
source must be refreshed and pinned before it supports a promotion decision.

## Domain references

[Native-frame references](native-frame.md) owns the exact ESP-IDF v5.4 source,
build-container digest, esptool 5.3.1 identity, publication dates, and refresh
points used by the ESP32-S3/native-frame domain. This index points to that
domain reference rather than duplicating its pins.

## Inspected RuView source

- Publisher/repository: ruvnet, [RuView](https://github.com/ruvnet/RuView).
- Inspected checkout: `/Users/murphy/code/github/oldRu/RuView`.
- Revision: [`0df48df7b256c772c83e9379e79a5ffdeb613ba4`](https://github.com/ruvnet/RuView/commit/0df48df7b256c772c83e9379e79a5ffdeb613ba4).
- Commit date: 2026-08-22T18:06:16-04:00.
- Provenance: local Git object and `origin` remote inspected on 2026-08-27.

The protected architecture cites this source for protocol, HAL/ontology,
training, benchmark, error-path, and synthetic-fallback comparisons. File and
line references in that legacy text apply only to the pinned checkout above.

## RF sensing and evaluation sources

| Source identity | Locator | Version/date in recovered source | Provenance |
| --- | --- | --- | --- |
| The Universal Language of CSI | [arXiv:2607.09727](https://arxiv.org/abs/2607.09727) | arXiv identifier recorded; version/date not recorded | Protected architecture; Zotero key `SNQMXYRW` |
| WiLLM implementation | [cjychenjiayi/WiLLM](https://github.com/cjychenjiayi/WiLLM) | Commit/date not recorded | Protected architecture; paired with Zotero `SNQMXYRW` |
| OpenCSI | Zotero item `2L4VHI3X` | Bibliographic version/date not recorded | Protected architecture; local Zotero identity only |
| CSI-Bench | Zotero item `FULL46UK` | Bibliographic version/date not recorded | Protected architecture; local Zotero identity only |
| Data-leakage review | Zotero item `XMUTVCW4` | Bibliographic version/date not recorded | Protected architecture; local Zotero identity only |
| CSI sampling nonuniformity source | Zotero item `J53NH6F7` | Bibliographic version/date not recorded | Protected architecture; local Zotero identity only |
| Espressif esp-csi | [espressif/esp-csi](https://github.com/espressif/esp-csi) | Commit/date not recorded | Protected architecture locator |
| CSIKit | [Gi-z/CSIKit](https://github.com/Gi-z/CSIKit) | Commit/date not recorded | Protected architecture locator |
| pyespargos | [ESPARGOS/pyespargos](https://github.com/ESPARGOS/pyespargos) | Commit/date not recorded | Protected architecture locator |
| Widar 3.0 | [project page](https://tns.thss.tsinghua.edu.cn/widar3.0/index.html) | Version/date not recorded | Protected architecture; Zotero key `EZCVW6XP` |
| WiFi-JEPA | [arXiv:2607.11064](https://arxiv.org/abs/2607.11064) | arXiv identifier recorded; version/date not recorded | Protected architecture; Zotero key `I4KFVKE2` |
| AM-FM | [arXiv:2602.11200](https://arxiv.org/abs/2602.11200) | arXiv identifier recorded; version/date not recorded | Protected architecture; Zotero key `XZSP43BE` |
| CAPC | [bornabr/CAPC](https://github.com/bornabr/CAPC) | Commit/date not recorded | Protected architecture; Zotero key `2R24BJAV` |
| DATTA | [arXiv:2411.13284](https://arxiv.org/abs/2411.13284) | arXiv identifier recorded; version/date not recorded | Protected architecture; Zotero key `SEEFUF22` |

The Zotero keys are stable local-library record identities, not substitutes for
publication metadata. Resolve and pin the underlying record before relying on
one for a roadmap promotion gate.

## Runtime and deployment sources

| Source identity | Locator | Version/date in recovered source | Provenance |
| --- | --- | --- | --- |
| ONNX Runtime CPU execution | [execution providers](https://onnxruntime.ai/docs/execution-providers/) | Documentation version/date not recorded | Protected architecture locator |
| ONNX Runtime on-device training | [training documentation](https://onnxruntime.ai/docs/get-started/training-on-device.html) | Documentation version/date not recorded | Protected architecture locator |
| ONNX Runtime threading | [threading documentation](https://onnxruntime.ai/docs/performance/tune-performance/threading.html) | Documentation version/date not recorded | Protected architecture locator |
| ONNX Runtime quantization | [quantization documentation](https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html) | Documentation version/date not recorded | Protected architecture locator |
| ONNX Runtime float16 conversion | [float16 documentation](https://onnxruntime.ai/docs/performance/model-optimizations/float16.html) | Documentation version/date not recorded | Protected architecture locator |

These locators establish where runtime claims were sourced. They do not pin a
Whisper backend or establish target-host performance.

## Model and architecture sources

| Source identity | Locator | Version/date in recovered source | Provenance |
| --- | --- | --- | --- |
| MiniMax H3 | [code](https://github.com/MiniMax-AI/MiniMax-H3), [model card](https://huggingface.co/MiniMaxAI/MiniMax-H3), [license](https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE) | Repository/model revision and access date not recorded | Protected architecture locators |
| MiniMax-M2 | [MiniMax-AI/MiniMax-M2](https://github.com/MiniMax-AI/MiniMax-M2) | Commit/date not recorded | Protected architecture locator |
| Grok-1 | [xai-org/grok-1](https://github.com/xai-org/grok-1), [release note](https://x.ai/news/grok-os) | Commit/release access date not recorded | Protected architecture locators |
| Cosmos 3 | [project](https://research.nvidia.com/labs/cosmos-lab/cosmos3/), [arXiv:2606.02800](https://arxiv.org/abs/2606.02800), [model matrix](https://docs.nvidia.com/cosmos/latest/cosmos3/model_matrix.html), [benchmarks](https://github.com/NVIDIA/cosmos/blob/main/inference_benchmarks.md) | ArXiv identifier recorded; web/repository revisions not recorded | Protected architecture locators |
| Qwen3-Omni | [QwenLM/Qwen3-Omni](https://github.com/QwenLM/Qwen3-Omni), [arXiv:2509.17765](https://arxiv.org/abs/2509.17765) | ArXiv identifier recorded; repository commit/date not recorded | Protected architecture locators |
| BAGEL | [ByteDance-Seed/Bagel](https://github.com/ByteDance-Seed/Bagel), [arXiv:2505.14683](https://arxiv.org/abs/2505.14683) | ArXiv identifier recorded; repository commit/date not recorded | Protected architecture locators |
| Emu3 and Emu3.5 | [baaivision/Emu3](https://github.com/baaivision/Emu3), [arXiv:2510.26583](https://arxiv.org/abs/2510.26583) | ArXiv identifier recorded; repository commit/date not recorded | Protected architecture locators |
| Gemma 4 | [announcement](https://blog.google/innovation-and-ai/technology/developers-tools/introducing-gemma-4-12b/), [arXiv:2607.02770](https://arxiv.org/abs/2607.02770) | ArXiv identifier recorded; announcement date not recorded | Protected architecture locators |
| DreamerV3 | [danijar/dreamerv3](https://github.com/danijar/dreamerv3), [Nature article](https://www.nature.com/articles/s41586-025-08744-2) | Article identifier recorded; repository commit/date not recorded | Protected architecture locators |
| V-JEPA 2 and 2.1 | [facebookresearch/vjepa2](https://github.com/facebookresearch/vjepa2), [arXiv:2506.09985](https://arxiv.org/abs/2506.09985), [arXiv:2603.14482](https://arxiv.org/abs/2603.14482) | ArXiv identifiers recorded; repository commit/date not recorded | Protected architecture locators |
| I-JEPA | [facebookresearch/ijepa](https://github.com/facebookresearch/ijepa) | Commit/date not recorded | Protected architecture locator |
| Perceiver IO | [DeepMind source](https://github.com/google-deepmind/deepmind-research/tree/master/perceiver), [arXiv:2107.14795](https://arxiv.org/abs/2107.14795) | ArXiv identifier recorded; repository commit/date not recorded | Protected architecture locators |
| ImageBind | [facebookresearch/ImageBind](https://github.com/facebookresearch/ImageBind) | Commit/date not recorded | Protected architecture locator |
| Mamba | [state-spaces/mamba](https://github.com/state-spaces/mamba) | Commit/date not recorded | Protected architecture locator |

Before any external code, weights, outputs, service, or runtime enters a
promotion decision, its exact revision, publication/access date, license, and
data provenance must be appended here or in a linked domain reference.
