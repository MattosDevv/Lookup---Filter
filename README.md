# 🚀 Lookup - Filter

Scanner de processos Windows **somente leitura** — detecta sinais de hooks e threads suspeitas sem modificar nenhum processo. Caso queiram ter uma base de como funciona basta ir nas seguintes pastas.
x64/
└── Release/
    └── Lookup - Filter.exe


Varre todos os processos em execução e procura por:

- **Inline Hook** — primeiros bytes de funções da `ntdll.dll` substituídos por instruções de desvio (`JMP`, `CALL`, `MOV RAX+JMP`, `PUSH+RET`, `INT3`)
- **EAT Hook** — endereço na Export Address Table aponta para fora do módulo
- **IAT Hook** — entrada na Import Address Table aponta para fora da `ntdll.dll` esperada
- **Thread estranha** — thread iniciada em endereço fora de qualquer módulo carregado

## Utilizaçao
> - O código demonstra a implementação de técnicas básicas de detecção
> - fácil de entender para que outros desenvolvedores possam estudar, aprimorar e expandir suas próprias implementações.
> - Sinta-se à vontade para utilizar este código como referência em seus projetos, adaptá-lo às suas necessidades e contribuir com melhorias.

## Como compilar

 > **Requisitos:** Visual Studio 2019 ou superior, Windows SDK 10.

1. Crie um projeto **Console Application** vazio em `x64`
2. Adicione os arquivos `Main.cpp`, `LookupFilter.cpp` e `LookupFilter.hpp`
3. Em **Project Properties**:
   - C/C++ → Language → C++ Language Standard → **ISO C++17**
   - Linker → Input → Additional Dependencies → adicione `Psapi.lib` e `ntdll.lib`
4. Compile em **Release x64** e execute como **Administrador**

## Saída

```
[!] Processo: exemplo.exe [PID: 1234]
    [>] função hookada
         - NtOpenProcess (inline/jmp-rel32)
    [+] thread estranha
         - 0x00007FF612340000

-----------------------------------------
 Processos escaneados : 91
 Processos suspeitos  : 2
```
