#ifndef SELECTION_H
#define SELECTION_H

#include <stddef.h>
#include <stdint.h>

#include "cve.h"

/* Uma CVE que o usuario buscou com sucesso no REPL e que fica persistida
 * em disco (output/selections.json), para um frontend futuro ler. */
typedef struct {
    char *cve_id;
    uint32_t year;
    CVEState state;
    char **products;
    size_t product_count;
} Selection;

typedef struct {
    Selection *items;
    size_t count;
    size_t capacity;
} SelectionArray;

void selection_array_free(SelectionArray *array);

/* Carrega as selecoes persistidas em `path`. Se o arquivo ainda nao
 * existir (primeira execucao), *array fica vazio e a funcao retorna
 * sucesso - isso NAO e' um erro. Outros erros (arquivo ilegivel, JSON
 * invalido) retornam 0. */
int selection_array_load_json(SelectionArray *array, const char *path);

/* Grava todas as selecoes em `path`: cria o diretorio pai se necessario,
 * escreve em um arquivo temporario e troca atomicamente pelo destino
 * (rename), para nunca deixar um arquivo corrompido/parcial se o
 * programa for interrompido no meio da escrita. */
int selection_array_save_json(const SelectionArray *array, const char *path);

/* Insere uma nova selecao ou substitui a existente com o mesmo cve_id
 * (sem duplicar por cve_id). Retorna 1 em sucesso, 0 em
 * falha de memoria. */
int selection_array_upsert(
    SelectionArray *array,
    const char *cve_id,
    uint32_t year,
    CVEState state,
    char *const *products,
    size_t product_count
);

#endif
