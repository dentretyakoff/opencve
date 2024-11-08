from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness
from cves.utils import extract_product_info


class BaseCveSerializer(serializers.ModelSerializer):
    nvd_versions = serializers.SerializerMethodField()

    def get_nvd_versions(self, obj):
        return extract_product_info(obj.nvd_json)

    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description", "nvd_versions"]


class CveListSerializer(BaseCveSerializer):
    class Meta(BaseCveSerializer.Meta):
        fields = ["created_at", "updated_at", "cve_id", "description", "nvd_versions"]


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
