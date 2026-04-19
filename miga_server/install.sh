#!/bin/bash

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите скрипт с правами root (sudo)."
    exit 1
fi

# Функция установки iptables без подтверждения
install_iptables() {
    if command -v iptables &> /dev/null; then
        echo "iptables уже установлен."
        return 0
    fi

    echo "Определение менеджера пакетов..."
    if command -v apt-get &> /dev/null; then
        echo "Установка iptables через apt-get..."
        apt-get update -qq
        apt-get install -y iptables
    elif command -v yum &> /dev/null; then
        echo "Установка iptables через yum..."
        yum install -y iptables
    elif command -v dnf &> /dev/null; then
        echo "Установка iptables через dnf..."
        dnf install -y iptables
    elif command -v zypper &> /dev/null; then
        echo "Установка iptables через zypper..."
        zypper install -y iptables
    elif command -v pacman &> /dev/null; then
        echo "Установка iptables через pacman..."
        pacman -S --noconfirm iptables
    else
        echo "Не удалось определить менеджер пакетов. Установите iptables вручную."
        exit 1
    fi

    if [ $? -eq 0 ]; then
        echo "iptables успешно установлен."
    else
        echo "Ошибка установки iptables."
        exit 1
    fi
}

# Функция настройки маскарада для всех реальных интерфейсов (кроме lo и tun)
configure_masquerade() {
    echo "Настройка маскарада для не-loopback и не-tun интерфейсов..."

    # Получаем список интерфейсов из /sys/class/net/, исключая lo и tun*
    for iface in $(ls /sys/class/net/ | grep -v -E '^lo$|^tun'); do
        # Дополнительная проверка, что интерфейс существует и поднят (опционально)
        if [ -d "/sys/class/net/$iface" ]; then
            echo "Добавляем правило MASQUERADE для интерфейса $iface"
            iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
            if [ $? -eq 0 ]; then
                echo "Правило для $iface добавлено."
            else
                echo "Ошибка добавления правила для $iface."
            fi
        fi
    done

    # Сохраняем правила (если есть служба сохранения iptables)
    if command -v iptables-save &> /dev/null; then
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
        elif command -v service iptables save &> /dev/null; then
            service iptables save
        else
            echo "Не удалось автоматически сохранить правила iptables. Сохраните их вручную."
        fi
    fi
}

# Функция регистрации демона (systemd)
register_systemd_service() {
    local SERVICE_FILE="/etc/systemd/system/miga_server.service"
    local EXEC_PATH="/usr/local/miga_server"

    if [ ! -x "$EXEC_PATH" ]; then
        echo "Ошибка: $EXEC_PATH не найден или не исполняемый."
        return 1
    fi

    echo "Создание systemd-сервиса для miga_server..."

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Miga Server
After=network.target

[Service]
Type=simple
ExecStart=$EXEC_PATH
Restart=on-failure
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    if [ $? -ne 0 ]; then
        echo "Ошибка создания файла сервиса."
        return 1
    fi

    systemctl daemon-reload
    systemctl enable miga_server
    if [ $? -eq 0 ]; then
        echo "Сервис miga_server включен в автозапуск."
    else
        echo "Ошибка включения автозапуска."
        return 1
    fi

    systemctl start miga_server
    if [ $? -eq 0 ]; then
        echo "Сервис miga_server запущен."
    else
        echo "Ошибка запуска сервиса. Проверьте журнал: journalctl -u miga_server"
        return 1
    fi

    return 0
}

# Основная часть
install_iptables

# Настройка маскарада
configure_masquerade

# Генерация ключей (однократная инициализация)
echo "Генерация ключей через /usr/local/miga_server --generate-keys..."
if [ -x "/usr/local/miga_server" ]; then
    /usr/local/miga_server --generate-keys
    if [ $? -ne 0 ]; then
        echo "Ошибка при генерации ключей."
        exit 1
    fi
else
    echo "Ошибка: /usr/local/miga_server не найден или не является исполняемым файлом."
    exit 1
fi

# Регистрация и запуск демона
if command -v systemctl &> /dev/null; then
    register_systemd_service
    if [ $? -eq 0 ]; then
        echo "Настройка демона завершена успешно."
    else
        echo "Не удалось настроить демон."
        exit 1
    fi
else
    echo "Предупреждение: systemd не обнаружен. Демон не зарегистрирован."
    echo "Для ручной настройки автозапуска используйте init.d или другой способ."
fi

echo "Готово. Сервер работает как демон."