FROM python:3.9-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1
# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝代码和静态资源
COPY . .

# 暴露端口
EXPOSE 5000

# 生产环境启动命令
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "app:app"]
