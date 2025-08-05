<template>
    <v-container>
        <v-data-table :headers="headers" :items="records" :items-per-page="-1" item-key="id" sort-by="name"
            class="elevation-1" :search="search" :clickable="false" @click.stop disable-pagination hide-default-footer>
            <template v-slot:top>
                <v-row v-bind="UI.TOOLBAR.ROW">
                    <v-col v-bind="UI.TOOLBAR.COL.LEFT">
                        <div :class="UI.CLASS.toolbar_filter_title">{{ $t('nav_menu.release_presets') }}</div>
                    </v-col>
                    <v-col v-bind="UI.TOOLBAR.COL.MIDDLE">
                        <v-text-field v-bind="UI.ELEMENT.SEARCH" v-model="search" :label="$t('toolbar_filter.search')"
                            single-line hide-details></v-text-field>
                    </v-col>
                    <v-col v-bind="UI.TOOLBAR.COL.RIGHT">
                        <v-btn v-bind="UI.BUTTON.ADD_NEW" @click="addItem">
                            <v-icon left>{{ UI.ICON.PLUS }}</v-icon>
                            <span>{{ $t('common.add_btn') }}</span>
                        </v-btn>
                    </v-col>
                </v-row>


            </template>

            <template v-slot:item.updated_at="{ item }">
                <span>{{ formatDate(item.updated_at) }}</span>
            </template>

            <template v-slot:item.actions="{ item }">
                <v-icon small class="mr-2" @click="editItem(item)">
                    mdi-pencil
                </v-icon>
                <v-icon small @click="deleteItem(item)">
                    mdi-delete
                </v-icon>
            </template>

        </v-data-table>
    </v-container>
</template>

<script>
import { createNewAiProvider, updateAiProvider, deleteAiProvider } from "@/api/config";
import AuthMixin from "@/services/auth/auth_mixin";
import Permissions from "@/services/auth/permissions";
import { format } from 'date-fns';
import Settings, { getSetting } from "@/services/settings";

export default {

    name: "AiProviderTable",
    props: {},
    data() {
        return {
            search: "",
            headers: [
                { text: this.$t('ai_provider.name'), value: 'name' },
                { text: this.$t('ai_provider.api_type'), value: 'api_type' },
                { text: this.$t('ai_provider.api_url'), value: 'api_url' },
                { text: this.$t('ai_provider.api_key'), value: 'api_key' },
                { text: this.$t('ai_provider.model'), value: 'model' },
                { text: this.$t('settings.updated_by'), value: 'updated_by' },
                { text: this.$t('settings.updated_at'), value: 'updated_at', filterable: false },
                { text: 'Actions', value: 'actions', sortable: false },
            ],
            records: [],
            dialogEdit: false,
            dialogDelete: false,
            editedItem: {
                id: -1,
                name: "",
                api_type: "",
                api_url: "",
                api_key: "",
                model: "",
            },
            defaultItem: {
                name: "Ollama - llama3:8b",
                api_type: "openai",
                api_url: "http://localhost:11434/v1",
                api_key: "secret",
                model: "llama3:8b"
            },
            date_format: ""
        };
    },
    mixins: [AuthMixin],
    computed: {
        dialogEditTitle() {
            return this.editedIndex === -1 ? this.$t("ai_provider.add_new") : this.$t("ai_provider.edit")
        },
    },
    watch: {
        dialogEdit(val) {
            val || this.closeEdit()
        },

        dialogDelete(val) {
            val || this.closeDelete()
        },
    },
    methods: {
        formatDate(dateString) {
            if (dateString) {
                return format(new Date(dateString), this.date_format);
            }
        },

        fetchRecords() {
            if (this.checkPermission(Permissions.CONFIG_AI_ACCESS)) {
                this.$store.dispatch('getAllAiProviders', { search: '' }).then(() => {
                    var dateFmt = getSetting(Settings.DATE_FORMAT);
                    var timeFmt = getSetting(Settings.TIME_FORMAT);
                    if (dateFmt != "" && timeFmt != "") {
                        this.date_format = dateFmt + " " + timeFmt;
                    } else {
                        this.date_format = "yyyy-MM-dd HH:mm:ss"; // Default format
                    }

                    this.records = this.$store.getters.getAiProviders.items;
                });
            }
        },

        addItem() {
            this.editedIndex = -1
            this.editedItem = Object.assign({}, this.defaultItem);
            this.dialogEdit = true;
        },

        editItem(item) {
            this.editedIndex = this.records.indexOf(item)
            this.editedItem = Object.assign({}, item)
            this.dialogEdit = true
        },

        deleteItem(item) {
            this.editedIndex = this.records.indexOf(item)
            this.editedItem = Object.assign({}, item)
            this.dialogDelete = true
        },

        closeEdit() {
            this.dialogEdit = false
        },

        closeDelete() {
            this.dialogDelete = false
        },

        saveRecord() {
            if (!this.$refs.form.validate()) return;
            if (this.editedIndex > -1) {
                updateAiProvider(this.editedItem).then((response) => {
                    this.editedItem = Object.assign({}, response.data)
                    Object.assign(this.records[this.editedIndex], this.editedItem);
                    this.showMsg("success", "ai_provider.successful_edit");
                    this.closeEdit();
                }).catch(() => {
                    this.showMsg("error", "ai_provider.error");
                })
            } else {
                createNewAiProvider(this.editedItem).then((response) => {
                    this.editedItem = Object.assign({}, response.data)
                    this.records.push(this.editedItem);
                    this.showMsg("success", "ai_provider.successful");
                    this.closeEdit();
                }).catch(() => {
                    this.showMsg("error", "ai_provider.error");
                })
            }
        },

        deleteRecord() {
            deleteAiProvider(this.editedItem).then(() => {
                this.records.splice(this.editedIndex, 1);
                this.showMsg("success", "ai_provider.remove");
                this.closeDelete();
            }).catch(() => {
                this.showMsg("error", "ai_provider.removed_error");
            })
        },

        showMsg(type, message) {
            this.$root.$emit('notification', { type: type, loc: message })
        },

    },
    mounted() {
        this.fetchRecords();
    }
}
</script>
