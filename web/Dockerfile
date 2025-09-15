FROM nginx:stable

# 기본 문서 제거
RUN rm -rf /usr/share/nginx/html/*

# ✅ Vite 빌드 산출물 통째로 복사
COPY ./dist /usr/share/nginx/html

# Nginx 설정
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

