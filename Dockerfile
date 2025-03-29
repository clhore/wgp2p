# Etapa de compilación: se utiliza la imagen oficial de Go para compilar la aplicación.
FROM golang:1.24.1 AS builder

# Establece el directorio de trabajo.
WORKDIR /app

# Copia los archivos de dependencias y descarga los módulos.
COPY go.mod go.sum ./
#RUN go mod download
RUN go mod tidy

# Copia el resto del código fuente.
COPY . .

# Compila la aplicación; ajusta el nombre del binario y opciones según necesites.
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o wgclient ./client-peer/main.go

# Etapa final: se utiliza una imagen base de Ubuntu.
FROM ubuntu:24.04

# Actualiza el sistema e instala certificados SSL necesarios.
RUN apt-get update && apt-get install -y ca-certificates wireguard iproute2 \
    openssh-server \
    iputils-ping

#&& rm -rf /var/lib/apt/lists/*

# Establece el directorio de trabajo en la imagen final.
WORKDIR /root/

# Copia el binario compilado desde la etapa de compilación.
COPY --from=builder /app/wgclient .

# Expone el puerto (ajústalo según tu aplicación).
EXPOSE 51820

CMD ["sleep", "infinity"]
