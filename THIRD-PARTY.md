# Third-party components and notices

No third-party source code is vendored in this repository. The project
*interoperates* with the components below; their code, models and licences are
not included here.

| component | relationship | licence / status |
|---|---|---|
| **Strata** (`Niko1221/Strata`) | external inference server; this project calls its HTTP API and recognises its processes | **MIT** — Copyright (c) 2026 Niko1221 and the Strata contributors. Notice reproduced below. Not bundled. |
| **Strata model weights** (e.g. the IQ2_XS quantisation in use) | loaded by Strata at runtime | **Not included. Redistribution terms are unclear** — the model's own licence applies and was not verified for this package. |
| **NVIDIA driver / CUDA / `nvidia-smi`** | proprietary runtime dependency | NVIDIA licence; not redistributed. |
| **systemd / systemd-logind** | service management, inhibitor and suspend API | LGPL-2.1+; API use only. |
| **GNOME / Mutter** | D-Bus idle monitor (`org.gnome.Mutter.IdleMonitor`) | GPL/LGPL; API use only. |
| **GTK 4 / libadwaita** | GUI toolkit used by `gui.py` | LGPL-2.1+; linked at runtime, not bundled. |
| **Sunshine** | remote-streaming service; the monitor reads its log and ports | GPL-3.0; no code copied. |
| **OpenCode** | agent runtime; the monitor reads its SQLite database read-only | No code copied. |
| **Python standard library** | runtime | PSF licence. |

## Strata notice (preserved)

The following notice is retained because this project depends on and
interoperates with Strata. It is the upstream project's notice, not a licence
for this repository.

```
MIT License

Copyright (c) 2026 Niko1221 and the Strata contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## File-level rights audit

Every file in the upload set was checked for third-party headers, copied code,
vendored libraries and external URLs. Result:

| file(s) | rights status |
|---|---|
| all `*.py`, `*.sh`, `*.pl`, `*.rules`, `*.desktop`, systemd units and drop-ins | **author's original work**; no third-party code, no copied headers |
| `docs/*.md`, `README.md`, `ARCHITECTURE.md` | **author's original text**; measurements of Strata are the author's observations, not copied documentation |
| `tests/*` | author's original tests |
| `config*.json` | author's original configuration, sanitized |
| `THIRD-PARTY.md` | contains the **Strata MIT notice**; reproduced under that licence and must be preserved in redistributions |

**No included file has unclear provenance.** What is unclear is the licence for
the author's own code: without a `LICENSE`, the default is "all rights
reserved", so publishing is a grant the author must choose to make.

## Unclear rights — action needed before publishing

- **This repository has no licence.** That is deliberate: the author has not
  chosen one. Until a `LICENSE` file is added, the default is "all rights
  reserved", which conflicts with publishing it as a portfolio piece.
- **Model weights are excluded and their redistribution terms were not
  verified.** They are not part of this upload set.
- **Strata source code is not included.** Its MIT notice is preserved above;
  including its code would require carrying that notice.
- **Screenshots or logs** from the live host were not included; if added later,
  check them for personal data and third-party content.
