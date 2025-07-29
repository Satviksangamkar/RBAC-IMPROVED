#!/bin/bash
# Permission Testing Script for Trading Terminal RBAC API
# This script verifies that role permissions are working correctly

echo "🔧 Testing Role Permissions for Trading Terminal RBAC API..."
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:8000"

# Function to check if server is running
check_server() {
    echo -e "${BLUE}Checking if server is running...${NC}"
    if curl -s $BASE_URL > /dev/null; then
        echo -e "${GREEN}✅ Server is running${NC}"
    else
        echo -e "${RED}❌ Server is not running. Please start with: python main.py${NC}"
        exit 1
    fi
}

# Function to get admin token
get_admin_token() {
    echo -e "${BLUE}Getting admin token...${NC}"
    ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=AdminSecure123!@#$" | \
        python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
    
    if [ -n "$ADMIN_TOKEN" ]; then
        echo -e "${GREEN}✅ Admin token obtained${NC}"
    else
        echo -e "${RED}❌ Failed to get admin token${NC}"
        exit 1
    fi
}

# Function to create test user
create_test_user() {
    local username=$1
    local password=$2
    local role=$3
    
    echo -e "${BLUE}Creating user: $username with role: $role${NC}"
    
    # Create user
    CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/users/" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}")
    
    if echo "$CREATE_RESPONSE" | grep -q "username"; then
        echo -e "${GREEN}✅ User $username created${NC}"
    else
        echo -e "${YELLOW}⚠️  User $username might already exist${NC}"
    fi
    
    # Assign role
    ROLE_RESPONSE=$(curl -s -X POST "$BASE_URL/users/assign-role" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"role_name\": \"$role\"}")
    
    if echo "$ROLE_RESPONSE" | grep -q "assigned"; then
        echo -e "${GREEN}✅ Role $role assigned to $username${NC}"
    else
        echo -e "${YELLOW}⚠️  Role assignment may have failed${NC}"
    fi
}

# Function to get user token
get_user_token() {
    local username=$1
    local password=$2
    
    USER_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&password=$password" | \
        python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
    
    if [ -n "$USER_TOKEN" ]; then
        echo -e "${GREEN}✅ $username logged in${NC}"
        echo "$USER_TOKEN"
    else
        echo -e "${RED}❌ Failed to login $username${NC}"
        return 1
    fi
}

# Function to test permissions
test_permission() {
    local user=$1
    local token=$2
    local test_name=$3
    local method=$4
    local endpoint=$5
    local data=$6
    local expected_code=$7
    
    echo -e "${BLUE}Testing: $user - $test_name${NC}"
    
    if [ "$method" = "GET" ]; then
        RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $token")
    elif [ "$method" = "POST" ]; then
        RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    if [ "$RESPONSE_CODE" = "$expected_code" ]; then
        echo -e "${GREEN}✅ $test_name: Expected $expected_code, got $RESPONSE_CODE${NC}"
    else
        echo -e "${RED}❌ $test_name: Expected $expected_code, got $RESPONSE_CODE${NC}"
    fi
}

# Function to show user permissions
show_permissions() {
    local user=$1
    local token=$2
    
    echo -e "${BLUE}Permissions for $user:${NC}"
    PERMS=$(curl -s -X GET "$BASE_URL/users/me/permissions" \
        -H "Authorization: Bearer $token")
    echo "$PERMS" | python3 -m json.tool 2>/dev/null || echo "Failed to get permissions"
    echo ""
}

# Main testing flow
main() {
    check_server
    get_admin_token
    
    echo ""
    echo -e "${YELLOW}Creating test users...${NC}"
    create_test_user "test_viewer" "ViewerPassword123!@#$" "viewer"
    create_test_user "test_trader" "TraderPassword123!@#$" "trader"
    
    echo ""
    echo -e "${YELLOW}Getting user tokens...${NC}"
    VIEWER_TOKEN=$(get_user_token "test_viewer" "ViewerPassword123!@#$")
    TRADER_TOKEN=$(get_user_token "test_trader" "TraderPassword123!@#$")
    
    echo ""
    echo -e "${YELLOW}Showing user permissions...${NC}"
    show_permissions "Admin" "$ADMIN_TOKEN"
    show_permissions "Trader" "$TRADER_TOKEN"
    show_permissions "Viewer" "$VIEWER_TOKEN"
    
    echo ""
    echo -e "${YELLOW}Testing VIEWER permissions...${NC}"
    test_permission "Viewer" "$VIEWER_TOKEN" "Access own profile" "GET" "/users/me" "" "200"
    test_permission "Viewer" "$VIEWER_TOKEN" "Execute trade (should fail)" "POST" "/trading/execute" '{"symbol":"AAPL","side":"buy","quantity":100,"order_type":"market"}' "403"
    test_permission "Viewer" "$VIEWER_TOKEN" "Create user (should fail)" "POST" "/users/" '{"username":"newuser","password":"Password123!@#$"}' "403"
    test_permission "Viewer" "$VIEWER_TOKEN" "Access admin endpoint (should fail)" "GET" "/admin/casbin-policies" "" "403"
    
    echo ""
    echo -e "${YELLOW}Testing TRADER permissions...${NC}"
    test_permission "Trader" "$TRADER_TOKEN" "Access own profile" "GET" "/users/me" "" "200"
    test_permission "Trader" "$TRADER_TOKEN" "Execute trade" "POST" "/trading/execute" '{"symbol":"AAPL","side":"buy","quantity":100,"order_type":"market"}' "200"
    test_permission "Trader" "$TRADER_TOKEN" "Create order" "POST" "/trading/orders" '{"symbol":"GOOGL","side":"buy","quantity":50,"order_type":"limit","price":150.00}' "200"
    test_permission "Trader" "$TRADER_TOKEN" "Get positions" "GET" "/trading/positions" "" "200"
    test_permission "Trader" "$TRADER_TOKEN" "Create user (should fail)" "POST" "/users/" '{"username":"newuser2","password":"Password123!@#$"}' "403"
    test_permission "Trader" "$TRADER_TOKEN" "Access admin endpoint (should fail)" "GET" "/admin/casbin-policies" "" "403"
    
    echo ""
    echo -e "${YELLOW}Testing ADMIN permissions...${NC}"
    test_permission "Admin" "$ADMIN_TOKEN" "Access own profile" "GET" "/users/me" "" "200"
    test_permission "Admin" "$ADMIN_TOKEN" "Execute trade" "POST" "/trading/execute" '{"symbol":"MSFT","side":"buy","quantity":200,"order_type":"market"}' "200"
    test_permission "Admin" "$ADMIN_TOKEN" "Create user" "POST" "/users/" '{"username":"admin_created_user","password":"Password123!@#$"}' "200"
    test_permission "Admin" "$ADMIN_TOKEN" "Create role" "POST" "/users/roles" '{"name":"test_role_123","description":"Test role"}' "200"
    test_permission "Admin" "$ADMIN_TOKEN" "Create permission" "POST" "/users/permissions" '{"name":"test:permission:123","description":"Test permission"}' "200"
    test_permission "Admin" "$ADMIN_TOKEN" "Access admin endpoint" "GET" "/admin/casbin-policies" "" "200"
    
    echo ""
    echo -e "${GREEN}🎉 Permission testing complete!${NC}"
    echo -e "${BLUE}Summary:${NC}"
    echo "- Viewer: Can only read data, cannot trade or administrate"
    echo "- Trader: Can trade and read data, cannot administrate"
    echo "- Admin: Can do everything (full permissions)"
}

# Run the tests
main 