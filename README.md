# Cifra-Musica

Sistema web para organizar, editar, transpor, apresentar e salvar cifras na nuvem. Preparado para publicação no GitHub Pages e para autenticação/biblioteca individual por usuário com Supabase.

**Slogan:** Suas cifras. Seu repertório. Em qualquer lugar.

## Arquivos

- `index.html` — sistema completo
- `config.js` — Project URL e chave pública do Supabase
- `supabase_setup.sql` — tabela `cifras`, índices e políticas RLS por usuário
- `.nojekyll` — compatibilidade com GitHub Pages
- `LEIA-ME-PRIMEIRO.txt` — passo a passo curto

## Repositório sugerido

`cifra-musica`

## Configuração da nuvem

1. Execute `supabase_setup.sql` no SQL Editor do Supabase.
2. Abra `config.js` e substitua os dois valores `COLE_AQUI...` pela **Project URL** e pela **Publishable/anon key** do projeto.
3. Nunca coloque a **Service Role Key** no front-end.

O banco usa Row Level Security (RLS): cada usuário autenticado só pode ler, inserir, alterar e excluir linhas cujo `user_id` seja o seu próprio usuário.

## GitHub Pages

Publique todos os arquivos na raiz do repositório e ative em **Settings > Pages > Deploy from a branch > main > /(root)**.
