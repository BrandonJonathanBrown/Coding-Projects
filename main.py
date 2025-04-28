from pytube import YouTube
from tqdm import tqdm
import requests
import os

# Author Brandon Jonathan Brown

class YouTubeDownloader:

    """ Constructor for YoutubeDownloader class """
    
    def __init__(self, url):
        print("[*] Initializing YouTube Downloader...")
        self.url = url
        self.video_data = None
        self.get_video_info()

    """ Function for retrieving video data from youtube sockets """
    
    def get_video_info(self):
        try:
            youtube = YouTube(self.url)
            streams = youtube.streams.filter(progressive=True, file_extension='mp4')
            if not streams:
                raise ValueError("No suitable streams found.")
            self.video_data = {
                "title": youtube.title,
                "streams": self.get_streams_info(streams)
            }
            print(f"[*] Video found: {self.video_data['title']}")
        except Exception as ex:
            print(f"[!] Error retrieving video info: {ex}")
            self.video_data = None

    """ Function for choosing the best resolution, proccessing the url from youtube, and lastly processing the file size """

    def get_streams_info(self, streams):
        stream_info = []
        for stream in streams:
            try:
                stream_info.append({
                    "resolution": stream.resolution,
                    "url": stream.url,
                    "filesize": stream.filesize or 0  # Handle None filesize
                })
            except Exception as ex:
                print(f"[!] Error fetching stream details: {ex}")
        return stream_info

    """ Function for downloading the video from youtube sockets """
    
    def download(self):
        if not self.video_data:
            print("[!] No video data available to download.")
            return
        try:
            highest_resolution_stream = max(
                self.video_data['streams'], key=lambda x: int(x['resolution'].replace('p', '') or 0)
            )
            title = self.video_data['title'].replace('/', '_').replace('\\', '_')  # Sanitize title
            file_name = f"{title}_highest_resolution.mp4"
            if os.path.exists(file_name):
                print(f"[!] File already exists: {file_name}")
                return
            print(f"[*] Downloading: {self.video_data['title']} ({highest_resolution_stream['resolution']})")
            response = requests.get(highest_resolution_stream['url'], stream=True)
            total_size = highest_resolution_stream['filesize']
            pbar = tqdm(total=total_size, unit='B', unit_scale=True)
            with open(file_name, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
            pbar.close()
            print(f"[*] Download successful: {file_name}")
        except Exception as ex:
            print(f"[!] Failed to download video: {ex}")


if __name__ == "__main__":

    """ Main function for input of youtube URL's and quit from application """
    urls = []
    while True:
        package = input("Please enter a URL or 'q' to quit: \n")
        if package.lower() == 'q':
            break
        urls.append(package)

    """ Loop through all the url's and download """
    
    for url in urls:
        downloader = YouTubeDownloader(url=url)
        downloader.download()

