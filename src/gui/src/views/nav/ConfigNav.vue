<template>
    <Navigation
            :links  = "links"
            :icon   = "'mdi-ballot-outline'"
            filter
    />
</template>

<script>
    import Navigation from "../../components/common/Navigation";

    export default {
        name: "ConfigNav",
        components: {
            Navigation
        },
        data: () => ({
            links: [
                { id: 1, icon: 'mdi-account-group', title: 'nav_menu.users', route: '/config/users', permission: 'CONFIG_USER_ACCESS', translate: '1' },
                { id: 2, icon: 'mdi-office-building', title: 'nav_menu.organizations', route: '/config/organizations', permission: 'CONFIG_ORGANIZATION_ACCESS', translate: '1' },
                { id: 3, icon: 'mdi-account-arrow-right', title: 'nav_menu.roles', route: '/config/roles', permission: 'CONFIG_ROLE_ACCESS', translate: '1' },
                { id: 4, icon: 'mdi-lock-check', title: 'nav_menu.acls', route: '/config/acls', permission: 'CONFIG_ACL_ACCESS', translate: '1' },
                { id: 5, separator: '1' },
                { id: 6, icon: 'mdi-server-network', title: 'nav_menu.collectors_nodes', route: '/config/collectors/nodes', permission: 'CONFIG_COLLECTORS_NODE_ACCESS', translate: '1' },
                { id: 7, icon: 'mdi-animation-outline', title: 'nav_menu.osint_sources', route: '/config/collectors/sources', permission: 'CONFIG_OSINT_SOURCE_ACCESS', translate: '1' },
                { id: 8, icon: 'mdi-folder-multiple', title: 'nav_menu.osint_source_groups', route: '/config/collectors/groups', permission: 'CONFIG_OSINT_SOURCE_GROUP_ACCESS', translate: '1' },
                { id: 9, separator: '1' },
                { id: 10, icon: 'mdi-server-network', title: 'nav_menu.presenters_nodes', route: '/config/presenters/nodes', permission: 'CONFIG_PRESENTERS_NODE_ACCESS', translate: '1' },
                { id: 12, icon: 'mdi-file-document-outline', title: 'nav_menu.product_types', route: '/config/product/types', permission: 'CONFIG_PRODUCT_TYPE_ACCESS', translate: '1' },
                { id: 13, separator: '1' },
                { id: 14, icon: 'mdi-server-network', title: 'nav_menu.publishers_nodes', route: '/config/publishers/nodes', permission: 'CONFIG_PUBLISHERS_NODE_ACCESS', translate: '1' },
                { id: 15, icon: 'mdi-file-star-outline', title: 'nav_menu.publisher_presets', route: '/config/publishers/presets', permission: 'CONFIG_PUBLISHER_PRESET_ACCESS', translate: '1' },
                { id: 16, separator: '1' },
                { id: 17, icon: 'mdi-application-variable-outline', title: 'nav_menu.attributes', route: '/config/reportitems/attributes', permission: 'CONFIG_ATTRIBUTE_ACCESS', translate: '1' },
                { id: 18, icon: 'mdi-file-table-outline', title: 'nav_menu.report_types', route: '/config/reportitems/types', permission: 'CONFIG_REPORT_TYPE_ACCESS', translate: '1' },
                { id: 19, separator: '1' },
                { id: 20, icon: 'mdi-server-network', title: 'nav_menu.bots_nodes', route: '/config/bots/nodes', permission: 'CONFIG_BOTS_NODE_ACCESS', translate: '1' },
                { id: 21, icon: 'mdi-robot', title: 'nav_menu.bot_presets', route: '/config/bots/presets', permission: 'CONFIG_BOT_PRESET_ACCESS', translate: '1' },
                { id: 22, separator: '1' },
                { id: 23, icon: 'mdi-remote-desktop', title: 'nav_menu.remote_access', route: '/config/remote/access', permission: 'CONFIG_REMOTE_ACCESS_ACCESS', translate: '1' },
                { id: 24, icon: 'mdi-share-variant', title: 'nav_menu.remote_nodes', route: '/config/remote/nodes', permission: 'CONFIG_REMOTE_NODE_ACCESS', translate: '1' },
                { id: 25, separator: '1' },
                { id: 26, icon: 'mdi-cog-outline', title: 'nav_menu.settings', route: '/config/settings', permission: 'CONFIG_SETTINGS_ACCESS', translate: '1' },
                { id: 27, icon: 'mdi-format-list-text', title: 'nav_menu.word_lists', route: '/config/wordlists', permission: 'CONFIG_WORD_LIST_ACCESS', translate: '1' },
                { id: 28, separator: '1' },
                { id: 29, icon: 'mdi-account-group', title: 'nav_menu.external_users', route: '/config/external/users', permission: 'MY_ASSETS_CONFIG', translate: '1' },
                { id: 30, icon: 'mdi-folder-multiple', title: 'nav_menu.asset_groups', route: '/config/external/groups', permission: 'MY_ASSETS_CONFIG', translate: '1' },
                { id: 31, icon: 'mdi-email-multiple-outline', title: 'nav_menu.notification_templates', route: '/config/external/templates', permission: 'MY_ASSETS_CONFIG', translate: '1' },
            ]
        })
    }
</script>
