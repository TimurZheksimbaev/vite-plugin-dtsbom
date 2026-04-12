# GitHub и публикация в npm

## 1. Репозиторий на GitHub
фыва asdfasdfa
1. Создай новый репозиторий на [github.com/new](https://github.com/new), например `vite-plugin-dtsbom` (без README, если уже есть локальный коммит).
2. Если имя пользователя на GitHub другое — поправь поля `repository`, `homepage` и `bugs` в `package.json`.
3. Привяжи remote и запушь:

```bash
cd /path/to/vite-plugin-dtsbom
git remote add origin git@github.com:YOUR_USERNAME/vite-plugin-dtsbom.git
git branch -M main
git push -u origin main
```

(Вместо SSH можно `https://github.com/YOUR_USERNAME/vite-plugin-dtsbom.git`.)

## 2. Публикация в npm (открытый пакет)

1. [Зарегистрируйся на npm](https://www.npmjs.com/signup) и войди в терминале: `npm login`.
2. Проверь, свободно ли имя: `npm view vite-plugin-dtsbom`. Если пакет уже занят — смени поле `name` в `package.json` (например, на `@твой-скоуп/vite-plugin-dtsbom` и публикуй как scoped).
3. Заполни `author` в `package.json` (имя и опционально email в формате `Name <email>`).
4. Собери и опубликуй:

```bash
npm run build
npm publish --access public
```

Флаг `--access public` нужен для scoped-пакетов (`@scope/name`); для не-scoped пакет и так публичный.

5. Проверка: `npm view vite-plugin-dtsbom` и установка в другом проекте: `npm i -D vite-plugin-dtsbom`.

Подробнее см. [PUBLISH.md](./PUBLISH.md).
