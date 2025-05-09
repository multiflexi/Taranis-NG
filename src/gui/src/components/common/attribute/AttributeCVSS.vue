<template>

    <!--<div>
        <v-row v-for="(value, index) in values" :key="value.index"
               class="valueHolder"
        >
            <v-col v-if="read_only || values[index].remote">
                <span>{{values[index].value}}</span>
            </v-col>

            <v-col v-if="!read_only && canModify && !values[index].remote" class="mt-6" style="flex-grow: 0">
                <CalculatorCVSS
                        :value="calcValue"
                        @update-value="updateValue"
                        @success="report"
                />
            </v-col>

            <v-col v-if="!read_only && !values[index].remote" cols="10">
                <v-text-field v-model="calcValue"
                              :label="$t('attribute.value')"
                              @focus="onFocus(index)" @blur="onBlur(index)" @keyup="directValueChange"
                              :class="getLockedStyle(index)"
                              :disabled="values[index].locked || !canModify"
                              :rules="[rules.vector]"
                ></v-text-field>
            </v-col>

        </v-row>
        <v-row justify="center">
            &lt;!&ndash; Score &ndash;&gt;
            <v-card class="text-center" color="white" outlined width="80%">
                <v-row justify="center">
                    <v-col v-for="metric in score.all" :key="metric.name" class="pa-0 mr-1 severity" :class="metric.severity" style="width: calc(100% / 3); border-radius: 4px;">
                        <span class="body-2 white&#45;&#45;text">{{ $t('cvss_calculator.'+metric.name+'_score') + " " }}</span>
                        <span class="body-2 white&#45;&#45;text font-weight-bold text-uppercase">{{ $t('cvss_calculator.' + metric.severity) }}</span>
                        <br>
                        <span class="px-4 cs_metric_score headline font-weight-medium">{{ metric.score }}</span>
                    </v-col>
                </v-row>
            </v-card>
        </v-row>
        <v-btn v-if="values.length < attribute_group.max_occurrence && !read_only && canModify" depressed small
               @click="add">
            <v-icon>mdi-plus</v-icon>
        </v-btn>
    </div>-->

    <AttributeItemLayout
            :add_button="addButtonVisible"
            @add-value="add()"
            :values="values"
    >
        <template v-slot:content>
            <v-row v-for="(value, index) in values" :key="value.index"
                   class="valueHolder"
            >
                <span v-if="read_only || values[index].remote">{{values[index].value}}</span>
                <AttributeValueLayout
                        v-if="!read_only && canModify && !values[index].remote"
                        :del_button="delButtonVisible"
                        @del-value="del(index)"
                        :occurrence="attribute_group.min_occurrence"
                        :values="values"
                        :val_index="index"
                >
                    <template v-slot:col_left>
                        <CalculatorCVSS
                                :value="calcValue"
                                @update-value="updateValue"
                                @success="report"
                        />
                    </template>
                    <template v-slot:col_middle>
                        <v-text-field v-model="calcValue"
                                      :label="$t('attribute.value')"
                                      @focus="onFocus(index)" @blur="onBlur(index)" @keyup="directValueChange"
                                      :class="getLockedStyle(index)"
                                      :disabled="values[index].locked || !canModify"
                                      :rules="[rules.vector]"
                        ></v-text-field>

                        <v-card class="text-center pb-3" flat>
                            <v-row justify="center">
                                <v-col v-for="metric in score.all" :key="metric.name" class="pa-0 mr-1 severity" :class="metric.severity" style="width: calc(100% / 3); border-radius: 4px;">
                                    <span class="body-2 white--text">{{ $t('cvss_calculator.'+metric.name+'_score') + " " }}</span>
                                    <span class="body-2 white--text font-weight-bold text-uppercase">{{ $t('cvss_calculator.' + metric.severity) }}</span>
                                    <br>
                                    <span class="px-4 cs_metric_score headline font-weight-medium">{{ metric.score }}</span>
                                </v-col>
                            </v-row>
                        </v-card>
                    </template>
                </AttributeValueLayout>
            </v-row>
        </template>
    </AttributeItemLayout>

</template>

<script>
    import AttributesMixin from "@/components/common/attribute/attributes_mixin";
    import CalculatorCVSS from "@/components/common/CalculatorCVSS";
    import Cvss31Mixin from "@/assets/cvss31_mixin";

    import AttributeItemLayout from "../../layouts/AttributeItemLayout";
    import AttributeValueLayout from "../../layouts/AttributeValueLayout";

    export default {
        name: "AttributeCVSS",
        props: {
            attribute_group: Object
        },
        data: () =>({
            score: "score status",
            calcValue: "",
            status: "",
            rules: {
                vector: value => {
                    const cvss2Pattern = /^AV:[NAL]\/AC:[HML]\/Au:[MSN]\/C:[NPC]\/I:[NPC]\/A:[NPC]$/;
                    const cvss3Pattern = /^CVSS:3\.[01]\/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|C:[HLN]|I:[HLN]|A:[HLN])\/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|C:[HLN]|I:[HLN]|A:[HLN])$/;
                    const cvss4Pattern = /^CVSS:4\.0\/(AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XHLN])?(\/MVI:[XHLN])?(\/MVA:[XHLN])?(\/MSC:[XHLN])?(\/MSI:[XSHLN])?(\/MSA:[XSHLN])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(X|Clear|Green|Amber|Red))?$/;
                    const floatPattern = /^(10(\.0)?|[0-9](\.[0-9])?)$/;

                    const pattern = new RegExp(`${cvss2Pattern.source}|${cvss3Pattern.source}|${cvss4Pattern.source}|${floatPattern.source}`);
                    return value == '' || pattern.test(value) || 'Invalid or Incomplete Vector String'
                }
            }
        }),
        mixins: [AttributesMixin,Cvss31Mixin],
        components: {
            CalculatorCVSS,
            AttributeItemLayout,
            AttributeValueLayout
        },
        computed: {
            /*putValue() {
                return this.values[0].value;
            }*/
        },
        methods: {
            updateValue(e) {
                this.calcValue = e;
                const value = parseFloat(e);
                if (value >= 0 && value <= 10) {
                    // OK
                }
                else {
                    this.score = this.clc.calculateCVSSFromVector(this.calcValue);
                }
                setTimeout(() => {
                    this.values[0].value = e;
                    this.onEdit(0);
                }, 200);
            },
            report(e) {
                this.status = e;
            },
            directValueChange() {
                const value = parseFloat(this.calcValue);
                if (value >= 0 && value <= 10) {
                    this.values[0].value = this.calcValue;
                    this.onKeyUp(0);
                }
                else if (this.calcValue.startsWith("CVSS:3.0/") || this.calcValue.startsWith("CVSS:4.0/") || this.calcValue.startsWith("AV:")) {
                    this.values[0].value = this.calcValue;
                    this.onKeyUp(0);
                }
                else {
                    let vsReport = this.clc.calculateCVSSFromVector(this.calcValue);
                    if (vsReport.success) {
                        this.score = vsReport;
                        this.values[0].value = this.calcValue;
                        this.onKeyUp(0);
                    }
                }
            }
        },
        mounted() {
            const value = parseFloat(this.values[0].value);
            if (value >= 0 && value <= 10) {
                this.calcValue = this.values[0].value;
            }
            else if (this.values[0].value !== "") {
                this.calcValue = this.values[0].value;
                this.score = this.clc.calculateCVSSFromVector(this.calcValue);
            } else {
                this.calcValue = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
            }
        }
    }
</script>
