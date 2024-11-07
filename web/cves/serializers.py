from rest_framework import serializers

from cves.models import Cve, Product, Vendor, Weakness


class CveListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description"]


class CveDetailSerializer(serializers.ModelSerializer):
    nvd_json = serializers.SerializerMethodField()

    def get_nvd_json(self, obj):
        return obj.nvd_json()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "description",
            "metrics",
            "weaknesses",
            "vendors",
            "nvd_json",
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
