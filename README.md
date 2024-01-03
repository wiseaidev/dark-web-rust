# 📚 Dark Web Rust

[![Work In Progress](https://img.shields.io/badge/Work%20In%20Progress-red)](https://github.com/wiseaidev)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/wiseaidev)
[![License](https://img.shields.io/badge/MIT-license-blue.svg)](https://opensource.org/licenses/MIT)
[![made-with-rust](https://img.shields.io/badge/Made%20with-Rust-1f425f.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Jupyter Notebook](https://img.shields.io/badge/Jupyter-Notebook-blue.svg?logo=Jupyter&logoColor=orange)](https://jupyter.org/)
[![Share On Reddit](https://img.shields.io/badge/share%20on-reddit-red?logo=reddit)](https://reddit.com/submit?url=https://github.com/wiseaidev/dark-web-rust&title=A%20hands-on%20book%20for%20abusing%20systems%20using%20Rust)
[![Share On Ycombinator](https://img.shields.io/badge/share%20on-hacker%20news-orange?logo=ycombinator)](https://news.ycombinator.com/submitlink?u=https://github.com/wiseaidev/dark-web-rust&t=A%20hands-on%20book%20for%20abusing%20systems%20using%20Rust)
[![Share On X](https://img.shields.io/badge/share%20on-X-03A9F4?logo=x)](https://twitter.com/share?url=https://github.com/wiseaidev/dark-web-rust&text=A%20hands-on%20book%20for%20abusing%20systems%20using%20Rust)
[![Share On Meta](https://img.shields.io/badge/share%20on-meta-1976D2?logo=meta)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/wiseaidev/dark-web-rust)
[![Share On Linkedin](https://img.shields.io/badge/share%20on-linkedin-3949AB?logo=linkedin)](https://www.linkedin.com/shareArticle?url=https://github.com/wiseaidev/dark-web-rust&title=A%20hands-on%20book%20for%20abusing%20systems%20using%20Rust)

## ⚠️ **Warning: Repository Content Alert**

> This repository contains an array of sophisticated methodologies that delve into the complex world of hacking and cybersecurity exploration. It is imperative to comprehend that using the tools and resources provided within this repository carries inherent risks that extend beyond the digital sphere. The utilization of these tools in any unauthorized manner may lead to severe legal consequences, including legal action and imprisonment. By accessing and experimenting with the contents provided, you do so entirely at your own risk, acknowledging the seriousness of the subject matter contained within. It is essential to emphasize that the purpose of this repository is strictly **educational** and **research-oriented**, aimed at promoting a deeper understanding of cybersecurity principles and vulnerabilities. Users are strongly advised to exercise utmost caution, adhere to ethical guidelines, and refrain from any activities that may breach legal boundaries. Remember, the responsibility lies solely with the user, and any misuse of the tools provided could have profound legal ramifications.

Welcome to the **Dark Web Rust** repository! This project is a continuum work of the [black-hat-rust](https://github.com/skerkour/black-hat-rust) book. Here, you'll delve into the world of networking, implementing low-level protocols, including IP, TCP, UDP, ICMP, and much more topics. The primary focus is on hands-on hacking methodologies, providing a comprehensive learning experience through Jupyter notebooks. Each chapter in this repository is also available in PDFs, Markdown, and other formats.

## 📝 Table of Contents

- [Installation](#-installation)
- [Chapters](#-chapters)
- [Licence](#-licence)
- [Star History](#-star-history)

## 🚀 Installation

To use the notebooks in this repository, you need to set up your environment. Follow these steps to get started:

1. Clone the repository to your local machine:

	```sh
	git clone https://github.com/wiseaidev/dark-web-rust.git
	```

1. Install the required dependencies and libraries. Make sure you have [`Rust`](https://rustup.rs/), [`Jupyter Notebook`](https://jupyter.org/install), and [`evcxr_jupyter`](https://github.com/evcxr/evcxr/blob/main/evcxr_jupyter/README.md) installed on your system.

	```sh
	# Install a Rust toolchain (e.g. nightly):
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

	# Install Jupyter Notebook
	pip install notebook

	# Install evcxr_jupyter
	cargo install evcxr_jupyter
	evcxr_jupyter --install	
	```

1. Navigate to the cloned repository:

	```sh
	cd dark-web-rust/chapter-1
	```

1. Start Jupyter Notebook:

	```sh
	jupyter notebook
	```

1. Access the notebooks in your web browser by clicking on the notebook file you want to explore.

## 📌 Chapters

| ID | Title | NB Pages | Topics | Open on GitHub | Launch on Binder | Read PDF |
|----|---------------|-----------|:-------------|-------------|----------------|-------|
| 1  | **Crafting a Rust-Based Network Sniffer** | 42 | - Introduction to Network Sniffers <br>- Rust for Network Programming <br>- The `socket2` Crate <br>- Fundamentals of Raw Network Packets in Rust<br>- Decoding different IP and Transport layers Packets in Rust<br>- How to build your own custom NMAP-like ports scanner | [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-1/chapter-1.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-1/chapter-1.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-1/chapter-1.pdf) |
| 2  | **Hidden Threads: Mastering the Art of Steganography in Rust** | 29 |  - Exploring the PNG File Format <br>- Reading amd Validating PNG Image Files <br>- Preprocessing PNG Images. <br>- Hiding Secrets with Steganography<br> | [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-2/chapter-2.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-2/chapter-2.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-2/chapter-2.pdf) |
| 3  | **Rust's Cryptographic Strengths and Vulnerabilities** | 23 |  - Cryptography in Rust <br>- Hashing <br>- Cracking MD5 Hashes<br> - Implementing bcrypt<br> - Message Authentication<br> - Symmetric Encryption<br>  - Asymmetric Encryption<br>| [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-3/chapter-3.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-3/chapter-3.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-3/chapter-3.pdf) |
| 4  | **Web Reconnaissance in Rust** | 26 |  - Web Reconnaissance and Social Engineering.<br>- Cookies management for persistent sessions.<br>- Crafting stealthy requests with custom user-agents.<br>- Leveraging proxies using Reqwest for enhanced security.<br>- Building a modular browser struct in Rust.<br>- Utilizing DuckDuckGo API for information gathering.<br>- Advanced interactions like image search and custom queries.<br>- Parsing Xeets in Rust for efficient data handling.<br>- Implementing anonymous email communication.<br>Mass social engineering techniques.| [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-4/chapter-4.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-4/chapter-4.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-4/chapter-4.pdf) |
| 5  | **The Dirty COW vulnerability in Rust** | 29+ |  - Memory Mapping.<br>- Applications of Memory Mapping.<br>- Memory-Mapped Database.<br>- Memory-Mapped Networking.<br>- Shared and Private Memory Mapping.<br>- Copy On Write (COW) Mechanism.<br>- Madvise System Call and Read-Only Files.| [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-5/chapter-5.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-5/chapter-5.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-5/chapter-5.pdf) |
| 6 | **SQL Injection in Rust?** | 8+ | - Memory Mapping.<br>- Applications of Memory Mapping.<br>- Memory-Mapped Database.<br>- Memory-Mapped Networking.<br>- Shared and Private Memory Mapping.<br>- Copy On Write (COW) Mechanism.<br>- Madvise System Call and Read-Only Files.| [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-5/chapter-5.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-5/chapter-5.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-5/chapter-5.pdf) |
| 6 | **SQL Injection in Rust** | 8+ |  - SQL Injection In `Rocket` and `SQLite`<br>- Gathering User Input.<br>- Fetching Data From the Database.<br>- SQL Injection Exploitation.<br>- SQL Injection Through cURL.<br>- SQL Injection Mitigation.| [![Github](https://img.shields.io/badge/launch-Github-181717.svg?logo=github&logoColor=white)](./chapter-6/chapter-6.ipynb) | [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/wiseaidev/dark-web-rust/main?filepath=chapter-6/chapter-6.ipynb) | [![nbviewer](https://img.shields.io/badge/Read%20PDF-nbviewer-blue)](https://nbviewer.org/github/wiseaidev/dark-web-rust/tree/main/chapter-6/chapter-6.pdf) |

## 📜 License

This project is licensed under the [MIT](https://opensource.org/licenses/MIT). For more details, You can refer to the [LICENSE](LICENSE) file.

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=wiseaidev/dark-web-rust&type=Date)](https://star-history.com/#wiseaidev/dark-web-rust&Date)

**Stay Ethical, Stay Legal. Use Responsibly.** ⚠️
