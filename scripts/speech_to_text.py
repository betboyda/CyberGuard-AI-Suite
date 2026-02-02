import os
import tempfile
import whisper
import moviepy.editor as mp

def transcribe_audio_from_video(video_path):
    # 1. Ses dosyasını videodan çıkar
    temp_audio_path = tempfile.mktemp(suffix=".mp3")
    video = mp.VideoFileClip(video_path)
    video.audio.write_audiofile(temp_audio_path, verbose=False, logger=None)

    # 2. Whisper modeli yükle ve transkript al
    model = whisper.load_model("base")  # veya "small", "medium"
    result = model.transcribe(temp_audio_path, language="tr")

    # 3. Geçici sesi sil
    os.remove(temp_audio_path)

    return result["text"]
