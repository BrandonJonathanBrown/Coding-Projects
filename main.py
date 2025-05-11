from yt_dlp import YoutubeDL
from tqdm import tqdm
import os

# Author: Brandon Jonathan Brown

""" Constructor """

class YouTubeDownloader:
    def __init__(self, url):
        print("[*] Initializing YouTube Downloader...")
        self.url = url
        self.title = None

""" Download function """

def download(self):
        try:
            print(f"[*] Fetching video info for: {self.url}")

            def hook(d):
                if d['status'] == 'downloading':
                    pbar.total = d.get('total_bytes', 0) or d.get('total_bytes_estimate', 0)
                    pbar.update(d.get('downloaded_bytes', 0) - pbar.n)
                elif d['status'] == 'finished':
                    print(f"\n[*] Download complete: {d['filename']}")

            ydl_opts = {
                'format': 'bestvideo+bestaudio/best',
                'outtmpl': '%(title)s.%(ext)s',
                'merge_output_format': 'mp4',
                'progress_hooks': [hook],
                'quiet': True,
                'noplaylist': True,
            }

            with tqdm(desc="Progress", unit='B', unit_scale=True, ncols=80) as pbar:
                with YoutubeDL(ydl_opts) as ydl:
                    ydl.download([self.url])

        except Exception as ex:
            print(f"[!] Failed to download video: {type(ex).__name__}: {ex}")

""" Main function """

if __name__ == "__main__":

    urls = []
    while True:
        print("YouTube Downloader - Brandon Jonathan Brown (yt-dlp edition)")
        url = input("Please enter a URL or 'q' to quit:\n").strip()
        if url.lower() == 'q':
            break
        urls.append(url)

    for url in urls:
        clean_url = url.split('&')[0]
        downloader = YouTubeDownloader(clean_url)
        downloader.download()


