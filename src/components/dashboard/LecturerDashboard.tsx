import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BookOpen, FileText, Users, Bell } from 'lucide-react';
import { Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';

interface Stats {
  courses: number;
  assignments: number;
  enrollments: number;
  announcements: number;
}

interface CourseSummary {
  id: string;
  code: string;
  name: string;
  status?: string | null;
}

interface AnnouncementSummary {
  id: string;
  title: string;
  status?: string | null;
}

export const LecturerDashboard = () => {
  const { user } = useAuth();
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
  const [stats, setStats] = useState<Stats>({
    courses: 0,
    assignments: 0,
    enrollments: 0,
    announcements: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      if (!user?.id) return;
      setLoading(true);
      try {
        const { data: coursesData, error: coursesError, count: courseCount } = await supabase
          .from('courses')
          .select('id, code, name, status', { count: 'exact' })
          .eq('lecturer_id', user.id);

        if (coursesError) throw coursesError;

        const courseIds = coursesData?.map((c) => c.id) || [];

        const countAssignments = async () => {
          if (courseIds.length === 0) return 0;
          const { count, error } = await supabase
            .from('assignments')
            .select('id', { count: 'exact', head: true })
            .in('course_id', courseIds);
          if (error) throw error;
          return count || 0;
        };

        const countEnrollments = async () => {
          if (courseIds.length === 0) return 0;
          const { count, error } = await supabase
            .from('enrollments')
            .select('id', { count: 'exact', head: true })
            .in('course_id', courseIds);
          if (error) throw error;
          return count || 0;
        };

        const [assignments, enrollments] = await Promise.all([
          countAssignments(),
          countEnrollments(),
        ]);

        const grouped = {
          pending: (coursesData || []).filter((c) => c.status === 'pending'),
          approved: (coursesData || []).filter((c) => c.status === 'approved' || !c.status),
          rejected: (coursesData || []).filter((c) => c.status === 'rejected'),
        };

        setCourseGroups(grouped);

        const { data: lecturerAnns, count: announcementCount } = await supabase
          .from('announcements')
          .select('id, title, status', { count: 'exact' })
          .eq('created_by', user.id);
        const groupedAnn = {
          pending: (lecturerAnns || []).filter((a) => a.status === 'pending'),
          approved: (lecturerAnns || []).filter((a) => a.status === 'approved' || !a.status),
          rejected: (lecturerAnns || []).filter((a) => a.status === 'rejected'),
        };
        setAnnouncementGroups(groupedAnn);

        setStats({
          courses: courseCount || 0,
          assignments,
          enrollments,
          announcements: announcementCount || 0,
        });
      } catch (error) {
        console.error('Error fetching lecturer stats:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, [user]);

  const quickCards = [
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
      title: 'Ghi danh',
      value: stats.enrollments,
      icon: <Users className="h-5 w-5 text-destructive" />,
      to: '/enrollments',
    },
    {
      title: 'Thông báo',
      value: stats.announcements,
      icon: <Bell className="h-5 w-5 text-warning" />,
      to: '/announcements',
    },
  ];

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-3xl font-bold text-foreground mb-2">Bảng điều khiển Giảng viên</h1>
        <p className="text-muted-foreground">Hệ thống quản lý của Giảng viên</p>
      </motion.div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {quickCards.map((card, idx) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * (idx + 1) }}
          >
            <Link to={card.to} className="block">
              <Card className="shadow-card hover:shadow-hover transition-shadow h-full">
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
          { title: 'Khóa học chờ duyệt', data: courseGroups.pending, badge: 'bg-warning/10 text-warning' },
          { title: 'Khóa học được duyệt', data: courseGroups.approved, badge: 'bg-success/10 text-success' },
          { title: 'Khóa học bị từ chối', data: courseGroups.rejected, badge: 'bg-destructive/10 text-destructive' },
        ].map((section, idx) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, x: idx === 0 ? -20 : idx === 2 ? 20 : 0 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.4 + idx * 0.1 }}
          >
            <Card className="shadow-card h-full">
              <CardHeader>
                <CardTitle>{section.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {section.data.length === 0 && (
                    <p className="text-sm text-muted-foreground">Không có khóa học</p>
                  )}
                  {section.data.map((course) => (
                    <div
                      key={course.id}
                      className="p-3 rounded-lg border border-border bg-accent/40"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-foreground">{course.code}</p>
                          <p className="text-sm text-muted-foreground">{course.name}</p>
                        </div>
                        <span className={`text-xs font-semibold px-2 py-1 rounded-full ${section.badge}`}>
                          {course.status || 'approved'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Announcement status sections */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        {[
          { title: 'Thông báo chờ duyệt', data: announcementGroups.pending, badge: 'bg-warning/10 text-warning' },
          { title: 'Thông báo được duyệt', data: announcementGroups.approved, badge: 'bg-success/10 text-success' },
          { title: 'Thông báo bị từ chối', data: announcementGroups.rejected, badge: 'bg-destructive/10 text-destructive' },
        ].map((section, idx) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, x: idx === 0 ? -20 : idx === 2 ? 20 : 0 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 + idx * 0.1 }}
          >
            <Card className="shadow-card h-full">
              <CardHeader>
                <CardTitle>{section.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {section.data.length === 0 && (
                    <p className="text-sm text-muted-foreground">Không có thông báo</p>
                  )}
                  {section.data.map((ann) => (
                    <div key={ann.id} className="p-3 rounded-lg border border-border bg-accent/40 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Bell className="h-4 w-4 text-primary" />
                        <p className="font-medium text-foreground">{ann.title}</p>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-1 rounded-full ${section.badge}`}>
                        {ann.status || 'approved'}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>
    </div>
  );
};
