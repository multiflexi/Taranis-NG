<template>
    <div>
        <v-snackbar dark v-model="notification" :color="notify.type">
            <div class="d-flex align-center">
                <span>{{ notificationMessage }}</span>
                <v-btn class="ml-auto" text color="white--text" @click="notification = false">{{$t('notification.close')}}</v-btn>
            </div>
        </v-snackbar>
    </div>
</template>

<script>
    export default {
        name: "Notification",

        props: {
        },

        data: () => ({
            notification: false,
            notify: Object
        }),

        computed: {
            notificationMessage() {
                if (this.notify && this.notify.loc) {
                    return this.$t(this.notify.loc, this.notify.params || {});
                }
                return '';
            }
        },

        mounted() {
            this.$root.$on('notification', (message) => {
                this.notification = true
                this.notify = message
            })
        }
    }
</script>
