1) Pobierz projekt:
    Sklonuj repozytorium lub skopiuj folder projektu ToDoListApp na swój komputer.

2) Upewnij się, że Docker działa

3) Otwórz terminal w folderze projektu:
    cd ../ToDoListApp

4) Zbuduj i uruchom aplikację:
    docker-compose up --build

    Ta komenda:
        - Zbuduje aplikację Flask oraz bazę PostgreSQL
        - Uruchomi oba kontenery
        - Aplikacja będzie dostępna pod adresem:
            http://localhost:5000

5) Domyślne konto administratora:
    Po pierwszym uruchomieniu aplikacji automatycznie utworzy się domyślne konto administratora:
        Login: admin
        Hasło: password123

6) W razie problemów upewnij się że kontenery z aplikacja (flask-app) oraz z bazą danych (todo-db) są uruchomione.