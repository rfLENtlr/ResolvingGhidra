#pragma once

/* Shared functions declaration */
void search_export_table_reference(app_pc pc);
void instrument_calls(app_pc pc);
void write_to_json();
void free_name_array();