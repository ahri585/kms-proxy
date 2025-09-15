# =======================
# React build → Nginx 서빙
# =======================

# Step 1: Nginx만 사용 (React 빌드 결과는 이미 dist/build 로 옮겨둔 상태)
FROM nginx:stable

# 기본 html 디렉토리 비움
RUN rm -rf /usr/share/nginx/html/*

# React build 결과물 복사
COPY ./build /usr/share/nginx/html

# Nginx 설정 덮어쓰기
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

