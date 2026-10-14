# infosul-assets
## Ferramentas externas

### rea/ (submódulo)

[REA: Reverse Engineer Anything](https://github.com/morluto/rea), servidor MCP de engenharia reversa (binários nativos, apps JavaScript/Electron, assemblies .NET e sites). Licença MIT.

Clonar este repositório já com o submódulo:

```bash
git clone --recurse-submodules https://github.com/infosulrs/infosul-assets
```

Se já clonou sem o submódulo:

```bash
git submodule update --init rea
```

Atualizar para a versão mais recente do REA:

```bash
git submodule update --remote rea
git add rea && git commit -m "Atualiza submódulo rea"
```
