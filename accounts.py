from fastapi import APIRouter, Depends

from auth_utils import check_bearer_token
import config

router = APIRouter()

@router.get("/core/v1/accounts/self")
async def accounts_self(auth_user_id: int = Depends(check_bearer_token)):
    """
    Возвращает профиль текущего пользователя (как в реальном Авито).
    """
    if auth_user_id == config.OWNER_ID:
        name = config.OWNER_NAME
        email = config.OWNER_EMAIL
        phone = config.OWNER_PHONE
        profile = config.OWNER_PROFILE_URL
    else:
        name = f"User {auth_user_id}"
        email = f"user{auth_user_id}@mock.local"
        phone = "70000000000"
        profile = f"https://avito.ru/user/mock/{auth_user_id}/profile"

    return {
        "email": email,
        "id": auth_user_id,
        "name": name,
        "phone": int(phone),
        "phones": [phone],
        "profile_url": profile,
    }
