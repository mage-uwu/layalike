# Laya weights

`laya/` is a copy of the Hugging Face model repo
[convaiinnovations/laya](https://huggingface.co/convaiinnovations/laya) at revision
`7b928d828b7b0e022f929d9bd2e44165aa270148`. The large files are stored with Git LFS, so run `git lfs pull` after cloning.

| Path | Checkpoint |
| --- | --- |
| `laya/` | English |
| `laya/multilingual/` | Multilingual |
| `laya/typed-decisions/` | Typed decisions |

Load them from disk instead of the Hub:

```python
import laya
agent = laya.load("weights/laya")
agent = laya.load("weights/laya", subfolder="multilingual")
```
