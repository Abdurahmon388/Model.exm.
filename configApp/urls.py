
from django.urls import path, include
from .views import *
from rest_framework.routers import DefaultRouter
from configApp.views import CourseApiView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


router = DefaultRouter()
router.register(r'teachers', TeacherViewSet, basename='teacher')
router.register(r'students', StudentViewSet)
router.register(r'department', DepartmentsApiView)
router.register(r'room', RoomAPIView)
router.register(r'day', DayAPIView)
router.register(r'group', GroupApiView)
router.register(r'tableType', TableTypeApi)
router.register(r'table', TableApi)
router.register(r'groupHome', GroupHomeWorkApi)
router.register(r'topic', TopicsApi)
router.register(r'homeWork', HomeWorkApi)
router.register(r'attendance-level', AttendanceLevelApi, basename='attendance-level')
router.register(r'parents', ParentsViewSet, basename='parent')
router.register(r'course', CourseApiView, basename='unique_course')


urlpatterns = [
    path('', include(router.urls)),
    path('user/', UserListView.as_view(), name='user-list'), 
    
    path('user/<int:id>/', UserDetailView.as_view(), name='user-detail'), 
    path('create/user/', UserCreateView.as_view(), name='user-create'), 
    path('update/user/<int:id>/', UserUpdateView.as_view(), name='user-update'), 
    path('delete/user/<int:id>/', UserDeleteView.as_view(), name='user-delete'),
    path('userApi/', RegisterUserApi.as_view()),
    path("statistics/", StatisticsView.as_view(), name="api_statistics_list"),
    path("enrollment/<int:pk>/", EnrollmentUpdateDeleteView.as_view(), name="enrollment_update_delete"),
    path('statistics/attendance-statistics/', AttendanceStatisticsView.as_view(), name='attendance-statistics'),
    path('statistics/courses-statistics/', CourseStatisticsView.as_view(), name='courses-statistics'),

    path('refresh_password/', ChangePasswordView.as_view()),
    path('sentOTP/', PhoneSendOTP.as_view()),
    path('sentOTP_and_phone/', VerifySms.as_view()),
    
    path('teacherAPI/', TeacherApiView.as_view()),
    path('teachers/',TeacherListView.as_view(),name="all_teachers"),
    path('teacher/<int:id>/',TeacherRetrieveAPIView.as_view(),name="teacher"),
    path('create/teacher/',TeacherCreateAPIView.as_view(),name='add_teacher'),
    path('create_user/', CreateUserView.as_view(), name='create_user'),
    path('update/teacher/<int:id>/',TeacherUpdateView.as_view(),name="update_teacher"),
    path('teacher-groups/<int:teacher_id>/',TeacherGroupsAPIView.as_view(),name="teacher_groups"),

    path('create/teacher/',TeacherCreateAPIView.as_view(),name='add_teacher'),
    path('update/teacher/<int:id>/',TeacherUpdateView.as_view(),name="update_teacher"),
    path('teacher-groups/<int:teacher_id>/',TeacherGroupsAPIView.as_view(),name="teacher_groups"),
    path('teachers/', TeacherListCreateView.as_view(), name='teacher-list-create'),
    path('teachers/<int:pk>/', TeacherDetailView.as_view(), name='teacher-detail'),
    path('comments/', CommentCreateView.as_view(), name='comment-create'),
    path('create/student/',StudentCreateAPIView.as_view(),name='add_student'),
    path('update/student/<int:id>/',StudentUpdateView.as_view(),name="update_student"),
    path('students-groups/', StudentGroupListView.as_view(), name='students-groups'),
    path('student-groups/<int:student_id>/', StudentGroupsAPIView.as_view(), name="student_groups"),
    path('students-by-ids/', StudentListByIdsAPIView.as_view(), name='students-by-ids'),

    path('group_get/', GroupApi.as_view()),
    path('group/', GroupListCreateView.as_view(), name='group-list-create'),
    path('group/<int:pk>/', GroupRetrieveUpdateDeleteView.as_view(), name='group-detail'),
    path('groups-by-ids/', GroupListByIdsAPIView.as_view(), name='groups-by-ids'),

    path('workerAPI/', WorkerApiView.as_view()),
    path('workerId/<int:pk>/', WorkerApiViewId.as_view()),
    path('student/', StudentApiView.as_view()),
    path('students/', StudentListView.as_view(), name='student-list'),
    path('api/students/', student_list_api, name='student-list-api'),
    path('student/<int:pk>/', StudentApiViewId.as_view()),
    path('students/',StudentListView.as_view(),name="all_students"),
    path('student/<int:id>/',StudentRetrieveAPIView.as_view(),name="student"),
    path('attendance-level/', AttendanceLevelView.as_view(), name='attendance-level'),

     # Ro'yxatdan o'tish (telefon raqam bilan)
    path('register/', RegisterView.as_view(), name='register'),

    # OTP orqali tasdiqlash
    path('verify/', VerifyOTPView.as_view(), name='verify'),

    # JWT login (token olish)
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),

    # JWT refresh token
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

