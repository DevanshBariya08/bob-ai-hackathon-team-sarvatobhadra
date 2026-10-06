# 🚀 Threat Intelligence Correlation Platform

> ⚠️ **Replace everything in `[ ]` brackets with your actual content before submission.**

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | SarvatoBhadra |
| **Track** | [AI / Web Application] |
| **Team Lead** | Devanshkumar Bariya — devansh.bariya05@gmail.com |
| **Members** | Princekumar Chudasama, Chiragbhai Bambhaniya, Manthanpuri Goswami,Sandip Jadav,Alpit Varvariya |

---

## 🎯 Problem Statement

> In 2–3 sentences: What problem does your project solve? Who experiences this problem?

Defence analysts receive thousands of heterogeneous alerts and intelligence reports every day from SIEM systems, cyber sensors, OSINT feeds, and intelligence sources. Manually analyzing this large volume of information makes it difficult to identify genuine threats, creates false-positive investigation overhead, and delays the production of actionable threat assessments required for timely decision-making.

---

## 💡 Solution

> In 2–3 sentences: What did you build? How does it solve the problem above?

We are building a Threat Intelligence Correlation Platform that ingests heterogeneous security data, normalizes it into a common structure, extracts entities and threat context using AI/NLP, and automatically correlates related alerts and reports. The platform scores and prioritizes threat clusters and generates evidence-backed BLUF assessments through a REST API and React dashboard, while keeping the human analyst in the decision loop.

---

## ✨ Key Features

- **Feature 1:** Multi-source data ingestion for SIEM alerts, OSINT data, intelligence reports, and structured files
- **Feature 2:** Data normalization and AI/NLP-based extraction of entities, indicators, threats, and contextual information
- **Feature 3:** Automated correlation of related alerts and intelligence from multiple independent sources
- **Feature 4:** Threat scoring and prioritization of correlated threat clusters
- **Feature 5:** AI-generated BLUF (Bottom Line Up Front) assessments for rapid analyst decision-making

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Java , Typescript |
| **Frameworks** | Spring Boot,React |
| **IBM Technologies** | [] |
| **Databases** | PostgreSQL, pgvector |
| **Other** | Docker, GitHub , Ollama |

---

## 📁 Repository Structure

```
├── src/                  # All source code
├── docs/                 # Written documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/                 # Demo artifacts
│   ├── screenshots/      # App screenshots
│   └── demo-video-link.txt  # Link to demo video
├── presentation/         # Slide deck
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

> **Copy these exact steps from your [`docs/setup-guide.md`](docs/setup-guide.md)**

```bash
# 1. Clone the repo
git clone https://github.com/[your-repo].git
cd [your-repo]

# 2. Install dependencies
[your install command here]

# 3. Configure environment
cp .env.example .env
# Edit .env with your values

# 4. Run the project
[your run command here]
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

---

## ⚠️ Known Limitations

> Be honest — judges appreciate transparency over overclaiming.

- The initial implementation relies on synthetic or simulated security data and focuses on demonstrating the complete correlation workflow; advanced integrations with real classified intelligence systems, large-scale production infrastructure, and fully validated threat intelligence feeds are outside the current prototype scope.


---

## 🏅 What We're Most Proud Of

Our strongest aspect is the end-to-end threat correlation pipeline that turns large volumes of heterogeneous security information into a small number of correlated and prioritized threat incidents. The platform combines AI/NLP extraction, semantic similarity, correlation, scoring, and evidence-backed BLUF generation while retaining human analyst validation for final decisions.

---
