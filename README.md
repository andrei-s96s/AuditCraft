# AuditCraft

Визуальный генератор правил [`auditd`](https://man7.org/linux/man-pages/man8/auditd.8.html) для Linux. Выберите пресеты, добавьте собственные пути и скачайте готовый файл `auditcraft.rules`.

## Публикация на GitHub Pages

1. Загрузите эти файлы в ветку `main` репозитория.
2. В GitHub откройте **Settings → Pages**.
3. В разделе **Build and deployment** выберите **Deploy from a branch**, ветку `main` и папку `/(root)`.
4. Сохраните настройки. Ссылка на сайт появится на этой же странице.

## Применение правил

Перед применением убедитесь, что все выбранные пути существуют на целевой машине. Поместите файл в `/etc/audit/rules.d/auditcraft.rules`, затем выполните:

```bash
sudo augenrules --load
sudo auditctl -l
```

Всегда сначала проверяйте правила в тестовой среде.
