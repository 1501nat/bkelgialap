import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { supabase } from '@/integrations/supabase/client';
import { Link } from 'react-router-dom';
import { BookOpen, FileText, Bell, Users, RotateCcw } from 'lucide-react';
import { toast } from 'sonner';

interface Stats {
  courses: number;
  assignments: number;
  announcements: number;
  users: number;
}

interface CourseSummary {
  id: string;
  code: string;
  name: string;
  lecturer_id: string | null;
  status: string;
}

interface AnnouncementSummary {
  id: string;
  title: string;
  created_by: string;
  status: string | null;
  is_global: boolean | null;
}

export const AdminDashboard = () => {
  const [stats, setStats] = useState<Stats>({
    courses: 0,
    assignments: 0,
    announcements: 0,
    users: 0,
  });
  const [loading, setLoading] = useState(true);
  const [courseGroups, setCourseGroups] = useState<{
    pending: CourseSummary[];
    approved: CourseSummary[];
    rejected: CourseSummary[];
  }>({ pending: [], approved: [], rejected: [] });
  const [announcementGroups, setAnnouncementGroups] = useState<{
    pending: AnnouncementSummary[];
    approved: AnnouncementSummary[];
    rejected: AnnouncementSummary[];
  }>({ pending: [], approved: [], rejected: [] });

  const fetchData = async () => {
    type TableName = 'courses' | 'assignments' | 'announcements' | 'profiles';
    const getCount = async (table: TableName) => {
      const { count, error } = await supabase
        .from(table)
        .select('id', { count: 'exact', head: true });
      if (error) throw error;
      return count || 0;
    };

    try {
      const [courses, assignments, announcements, users] = await Promise.all([
        getCount('courses'),
        getCount('assignments'),
        getCount('announcements'),
        getCount('profiles'),
      ]);

      setStats({ courses, assignments, announcements, users });

      // Fetch all courses
      const { data: allCourses } = await supabase
        .from('courses')
        .select('id, code, name, lecturer_id, status');

      const coursesData = allCourses || [];
      setCourseGroups({
        pending: coursesData.filter((c) => c.status === 'pending'),
        approved: coursesData.filter((c) => c.status === 'approved'),
        rejected: coursesData.filter((c) => c.status === 'rejected'),
      });

      // Fetch global announcements
      const { data: allAnnouncements } = await supabase
        .from('announcements')
        .select('id, title, created_by, status, is_global')
        .eq('is_global', true);

      const announcementsData = allAnnouncements || [];
      setAnnouncementGroups({
        pending: announcementsData.filter((a) => a.status === 'pending'),
        approved: announcementsData.filter((a) => a.status === 'approved' || !a.status),
        rejected: announcementsData.filter((a) => a.status === 'rejected'),
      });
    } catch (err) {
      console.error('Error fetching admin stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCourseAction = async (courseId: string, newStatus: string) => {
    const { error } = await supabase
      .from('courses')
      .update({ status: newStatus })
      .eq('id', courseId);

    if (error) {
      toast.error('Có lỗi xảy ra');
    } else {
      toast.success(newStatus === 'approved' ? 'Đã duyệt khóa học' : 'Đã từ chối khóa học');
      fetchData();
    }
  };

  const handleAnnouncementAction = async (announcementId: string, newStatus: string) => {
    const { error } = await supabase
      .from('announcements')
      .update({ status: newStatus })
      .eq('id', announcementId);

    if (error) {
      toast.error('Có lỗi xảy ra');
    } else {
      toast.success(newStatus === 'approved' ? 'Đã duyệt thông báo' : 'Đã từ chối thông báo');
      fetchData();
    }
  };

  const cards = [
    {
      title: 'Khóa học',
      value: stats.courses,
      icon: <BookOpen className="h-5 w-5 text-primary" />,
      to: '/courses',
    },
    {
      title: 'Bài tập',
      value: stats.assignments,
      icon: <FileText className="h-5 w-5 text-success" />,
      to: '/assignments',
    },
    {
      title: 'Thông báo',
      value: stats.announcements,
      icon: <Bell className="h-5 w-5 text-warning" />,
      to: '/announcements',
    },
    {
      title: 'Người dùng',
      value: stats.users,
      icon: <Users className="h-5 w-5 text-destructive" />,
      to: '/users',
    },
  ];

  const renderCourseItem = (course: CourseSummary, showReapprove: boolean, showActions: boolean) => (
    <div key={course.id} className="p-3 rounded-lg border border-border bg-accent/40">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium text-foreground">{course.code}</p>
          <p className="text-sm text-muted-foreground">{course.name}</p>
        </div>
        <div className="flex gap-2">
          {showActions && (
            <>
              <button
                className="text-sm px-3 py-1 rounded-md bg-success/10 text-success hover:bg-success/20 transition-colors"
                onClick={() => handleCourseAction(course.id, 'approved')}
              >
                Duyệt
              </button>
              <button
                className="text-sm px-3 py-1 rounded-md bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors"
                onClick={() => handleCourseAction(course.id, 'rejected')}
              >
                Từ chối
              </button>
            </>
          )}
          {showReapprove && (
            <button
              className="text-sm px-3 py-1 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors flex items-center gap-1"
              onClick={() => handleCourseAction(course.id, 'approved')}
            >
              <RotateCcw className="h-3 w-3" />
              Duyệt lại
            </button>
          )}
        </div>
      </div>
    </div>
  );

  const renderAnnouncementItem = (ann: AnnouncementSummary, showReapprove: boolean, showActions: boolean) => (
    <div key={ann.id} className="p-3 rounded-lg border border-border bg-accent/40">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-primary" />
          <p className="font-medium text-foreground">{ann.title}</p>
        </div>
        <div className="flex gap-2">
          {showActions && (
            <>
              <button
                className="text-sm px-3 py-1 rounded-md bg-success/10 text-success hover:bg-success/20 transition-colors"
                onClick={() => handleAnnouncementAction(ann.id, 'approved')}
              >
                Duyệt
              </button>
              <button
                className="text-sm px-3 py-1 rounded-md bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors"
                onClick={() => handleAnnouncementAction(ann.id, 'rejected')}
              >
                Từ chối
              </button>
            </>
          )}
          {showReapprove && (
            <button
              className="text-sm px-3 py-1 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors flex items-center gap-1"
              onClick={() => handleAnnouncementAction(ann.id, 'approved')}
            >
              <RotateCcw className="h-3 w-3" />
              Duyệt lại
            </button>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-3xl font-bold text-foreground mb-2">Bảng điều khiển Quản trị viên</h1>
        <p className="text-muted-foreground">Quản lý toàn bộ hệ thống</p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {cards.map((card, index) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * (index + 1) }}
          >
            <Link to={card.to}>
              <Card className="shadow-card hover:shadow-hover transition-shadow">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground">
                    {card.title}
                  </CardTitle>
                  {card.icon}
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-foreground">
                    {loading ? '...' : card.value}
                  </div>
                </CardContent>
              </Card>
            </Link>
          </motion.div>
        ))}
      </div>

      {/* Course status sections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {[
          { title: 'Khóa học chờ duyệt', data: courseGroups.pending, showActions: true, showReapprove: false },
          { title: 'Khóa học đã duyệt', data: courseGroups.approved, showActions: false, showReapprove: false },
          { title: 'Khóa học đã từ chối', data: courseGroups.rejected, showActions: false, showReapprove: true },
        ].map((section, idx) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, x: idx === 0 ? -20 : idx === 2 ? 20 : 0 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 + idx * 0.1 }}
          >
            <Card className="shadow-card h-full">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BookOpen className="h-5 w-5" />
                  {section.title}
                  <span className="text-sm font-normal text-muted-foreground">({section.data.length})</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-[300px] overflow-y-auto">
                  {section.data.length === 0 && (
                    <p className="text-sm text-muted-foreground">Không có khóa học</p>
                  )}
                  {section.data.map((course) => renderCourseItem(course, section.showReapprove, section.showActions))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Announcement status sections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        {[
          { title: 'Thông báo chờ duyệt', data: announcementGroups.pending, showActions: true, showReapprove: false },
          { title: 'Thông báo đã duyệt', data: announcementGroups.approved, showActions: false, showReapprove: false },
          { title: 'Thông báo đã từ chối', data: announcementGroups.rejected, showActions: false, showReapprove: true },
        ].map((section, idx) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, x: idx === 0 ? -20 : idx === 2 ? 20 : 0 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 + idx * 0.1 }}
          >
            <Card className="shadow-card h-full">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  {section.title}
                  <span className="text-sm font-normal text-muted-foreground">({section.data.length})</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-[300px] overflow-y-auto">
                  {section.data.length === 0 && (
                    <p className="text-sm text-muted-foreground">Không có thông báo</p>
                  )}
                  {section.data.map((ann) => renderAnnouncementItem(ann, section.showReapprove, section.showActions))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>
    </div>
  );
};
