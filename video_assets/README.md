# Aegis Video Production Assets 🎥

This directory contains the timed transcript, subtitles, and instructions for generating the studio-quality AI voiceover for **`Aegis verification.mp4`** (67.36 seconds).

---

## 📁 Files in This Directory

* **[`transcript.txt`](transcript.txt):** The clean, unformatted text ready to copy-paste into [ElevenLabs](https://elevenlabs.io/).
* **[`subtitles.srt`](subtitles.srt):** Standard SubRip subtitle file with millisecond timestamps timed to the video.
* **[`subtitles.vtt`](subtitles.vtt):** WebVTT subtitle file for HTML5 web players, GitHub, and `mobin.tech`.

---

## 🎙️ Step-by-Step Voiceover Generation (ElevenLabs)

1. Go to **[elevenlabs.io](https://elevenlabs.io/)** (free tier account).
2. Go to **Text to Speech**.
3. Select an authoritative, calm engineering voice:
   * **Recommended:** **"Adam"** (American, deep, professional) or **"Daniel"** (British, authoritative).
4. Open [`transcript.txt`](transcript.txt), copy all text, and paste it into ElevenLabs.
5. Set **Voice Settings**:
   * *Stability:* 65%
   * *Clarity + Similarity:* 75%
   * *Speed:* 1.0x (Normal)
6. Click **Generate speech**.
7. Click the **Download** button and save the file as `voiceover.mp3` in this folder.

---

## 🎬 Merging the Audio With Your Video

Once you download `voiceover.mp3`, you can merge it with `Aegis verification.mp4` in 30 seconds:

### Method A: Built-in Windows Clipchamp (Visual)
1. Right-click `Aegis verification.mp4` ➔ **Open with** ➔ **Clipchamp**.
2. Drag `voiceover.mp3` into the timeline directly beneath the video track.
3. Align the start of the audio with the start of the video.
4. Click **Export** (top right) ➔ **1080p**.

### Method B: PowerShell / FFmpeg (Instant 1-Command Merge)
If you place `voiceover.mp3` in this folder, you can run:
```powershell
ffmpeg -i "..\Aegis verification.mp4" -i "voiceover.mp3" -c:v copy -c:a aac -shortest "..\Aegis_Official_Demo.mp4"
```
