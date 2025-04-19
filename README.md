# Urlbox Screenshots

Batch-capture URLs to AVIF screenshots via the Urlbox API, with rate-limit handling and parallel execution.

## Features

- Parallel screenshot capture (configurable worker count)
- Desktop and mobile viewport support
- Built-in rate-limit management (auto-waits/retries)
- Logs successful and failed URLs separately
- Blacklist support to skip unwanted domains/patterns
- Dry-run and count-limiting options for safe testing

## Prerequisites

- Python 3.6 or newer
- [Urlbox API account](https://urlbox.com/screenshot-api) with public & secret keys

## Installation

1. Clone this repository: 

```bash 
git clone https://github.com/alexfertel/urlbox-screenshots.git 
cd urlbox-screenshots
```

2. Create a `.env` file in the project root with your keys: 

```ini
URLBOX_PUBLIC_KEY=your_public_key_here 
URLBOX_SECRET_KEY=your_secret_key_here 
```

## Usage
Place your input JSON with URLs under data/urls.json. Format:

```json
[
  {
    "websites": [
      { "url": "https://example.com" },
    ]
  },
  ...
]
```

Run the script:

```bash 
uv run main.py [options]
```

Options:

- -n,   --dry-run    Process only the first new URL and exit
- -w N, --workers N  Use N parallel workers (default: 5)
- -c M, --count M    Stop after M screenshots
- -m,   --mobile     Capture mobile viewport only

Screenshots are saved in `screenshots/`. Progress is logged to:

- `data/processed-urls.txt`
- `data/errored-urls.txt`

## Blacklist

Add URL prefixes to `data/blacklist.txt` (one per line) to skip certain domains or patterns.

## Contributing

- Fork the repository
- Create a feature branch (`git checkout -b feature/my-feature`)
- Commit your changes (`git commit -m "Add feature"`)
- Push to branch (`git push origin feature/my-feature`)
- Open a pull request

Please follow the existing code style and add tests for new functionality.

## License

This project is licensed under the MIT License. See (LICENSE)[./LICENSE] for details.

## Acknowledgments

Screenshots Sponsored by Urlbox

Urlbox is the most mature and accurate [website screenshot API](https://urlbox.com/screenshot-api). Turn any URL or HTML document into pixel-perfect images, PDFs or video. Remove banners, popups and other ugly glitches. You can even extract data and text at the same time.
