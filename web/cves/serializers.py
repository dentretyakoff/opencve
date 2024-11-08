from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness
from cves.utils import extract_product_info


class BaseCveSerializer(serializers.ModelSerializer):
    nvd_versions = serializers.SerializerMethodField()
    cvss_metric = serializers.SerializerMethodField()

    def get_nvd_versions(self, obj):
        return extract_product_info(obj.nvd_json)

    def get_cvss_metric(self, obj):
        return max(
            obj.cvssV2_0.get("score", 0),
            obj.cvssV3_0.get("score", 0),
            obj.cvssV3_1.get("score", 0),
            obj.cvssV4_0.get("score", 0),
        )

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "description",
            "nvd_versions",
            "cvss_metric",
            # "exploitation"
        ]


class CveListSerializer(BaseCveSerializer):
    class Meta(BaseCveSerializer.Meta):
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "description",
            "nvd_versions",
            "cvss_metric",
        ]


class CveDetailSerializer(BaseCveSerializer):
    class Meta(BaseCveSerializer.Meta):
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "description",
            "metrics",
            "weaknesses",
            "vendors",
            "nvd_versions",
            "cvss_metric",
        ]


class WeaknessListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Weakness
        fields = [
            "created_at",
            "updated_at",
            "cwe_id",
        ]


class VendorListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]


class ProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]
