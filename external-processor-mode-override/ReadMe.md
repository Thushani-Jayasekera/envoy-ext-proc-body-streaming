Terminal 1
envoy-ext-proc-body-streaming-renuka-main % docker-compose up --build

Terminal 2
external-processor-mode-override % go run main.go -write_data_to_file=true
2024/06/19 17:44:11 Starting external processor on port 9003

Terminal 3
streaming-backend % go run main.go -write_to_file=true
2024/06/19 17:44:15 Starting streaming backend on port 8889

Terminal 4
streaming-client % go run main.go -file ../resources/roar.mp4 -url http://localhost:18081/stream-upload
2026/02/27 15:32:40 Uploading ../resources/roar.mp4 to http://localhost:18081/stream-upload

Terminal 5
envoy-ext-proc-body-streaming-renuka-main % cat temp/1772186572450520000-chunk-{0001..1191}.mp4 > temp/preview.mp4
envoy-ext-proc-body-streaming-renuka-main % open temp/preview.mp4    
This can be played successfully, confirming that the streaming upload worked end-to-end with the FDS mode override.
