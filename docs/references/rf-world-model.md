# RF world-model provenance

These sources were selected in the frozen design reviewed on 2026-09-05. The
specification defines Whisper's own engineering composition; no paper or
repository validates the complete proposed system or grants it upstream
accuracy. Importing code/weights still requires its exact license and data
provenance to be recorded by the corresponding implementation ticket.

| Source | Fixed reference / purpose |
| --- | --- |
| ESPARGOS | [pyespargos 6967d98](https://github.com/ESPARGOS/pyespargos/tree/6967d98d321732d716ba8b1a48fdeeee22438c3b/demos): concrete locally coherent array and calibration reference |
| RuView | [2e9e87c calibration](https://github.com/ruvnet/RuView/blob/2e9e87c65c23ef901a45e1b03480ae3f8dc6a9c9/aether-arena/calibration/calibrate.py), [39f46e5 model artifact](https://huggingface.co/ruvnet/wifi-densepose-mmfi-pose/tree/39f46e583081a577bddd72f239690281ec11644b): qualified comparison sources, with clean data/selection protocol |
| Person-in-WiFi 3D | [468aff3 implementation](https://github.com/aiotgroup/Person-in-WiFi-3D-repo/blob/468aff35f0b042671b88bd22dc19428e5152f593/configs/wifi/petr_wifi.py): multi-receiver set prediction and real multi-person supervision |
| mD-Track | [Original paper](https://xieyaxiongfly.github.io/CSE610_UB/_files/paper/md_track.pdf): multi-parameter RF path interpretation |
| CRF | [arXiv:1011.4088](https://arxiv.org/abs/1011.4088): structured conditional prediction; Whisper's causal joint state is its own design |
| OpenCSI | [Paper v1](https://arxiv.org/html/2607.26665v1): dense-link occupancy and calibration evidence within its deployment scope |
| RoomPlan | [Apple WWDC 2023](https://developer.apple.com/videos/play/wwdc2023/10192/): phone scanning/session continuation and spatial capture |
| Nexmon CSI | [Native format documentation](https://github.com/seemoo-lab/nexmon_csi#analyzing-the-csi): multi-packet measurement example; not a mandatory second driver |
| RFIR | [arXiv:2604.07086v1](https://arxiv.org/html/2604.07086v1): geometry-assisted RF modeling, not unique unknown-material recovery |
| Differentiable ray tracing | [arXiv:2311.18558](https://arxiv.org/abs/2311.18558): bounded physics-assisted calibration, not a first-version inverse-rendering prerequisite |

Array reference results do not apply to ordinary single-path ESP measurements.
An upstream pose model is comparable only where inputs, labels, coordinates and
task meaning actually agree. Training and model selection partitions must be
audited before any competitive claim.
