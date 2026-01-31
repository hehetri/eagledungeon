# Dungeon Toolkit

Este repositorio contem duas ferramentas para trabalhar com `dungeon.bin`:

* `dungeon_extract.py` - extrai e descriptografa os arquivos `.dun`.
* `dungeon_pack.py` - reempacota os arquivos descriptografados usando o mesmo esquema.

## Uso

### Extracao

```bash
python dungeon_extract.py dungeon.bin output --manifest manifest.json
```

### Reempacotar

```bash
python dungeon_pack.py output manifest.json dungeon_new.bin
```

O manifesto contem o cabecalho original, a ordem dos arquivos e a chave usada para a criptografia.

## Observacoes

Se alguns arquivos nao existirem no `dungeon.bin`, o extractor cria arquivos vazios e emite avisos no stderr. O compactador reutiliza esses arquivos vazios, mantendo a mesma criptografia para os demais dados.
