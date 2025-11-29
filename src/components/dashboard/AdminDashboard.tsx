import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Users, BookOpen, FileText, Settings, TrendingUp, UserPlus } from 'lucide-react';
import { Link } from 'react-router-dom';

export const AdminDashboard = () => {
  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-3xl font-bold text-foreground mb-2">Bảng điều khiển Admin</h1>
        <p className="text-muted-foreground">Quản lý toàn bộ hệ thống</p>
      </motion.div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card className="shadow-card hover:shadow-hover transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Tổng Sinh viên
              </CardTitle>
              <Users className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">5,234</div>
              <p className="text-xs text-success">+12% từ tháng trước</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="shadow-card hover:shadow-hover transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Giảng viên
              </CardTitle>
              <Users className="h-4 w-4 text-success" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">342</div>
              <p className="text-xs text-success">+5% từ tháng trước</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="shadow-card hover:shadow-hover transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Khóa học
              </CardTitle>
              <BookOpen className="h-4 w-4 text-warning" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">156</div>
              <p className="text-xs text-muted-foreground">Đang hoạt động</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="shadow-card hover:shadow-hover transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Tỷ lệ hoạt động
              </CardTitle>
              <TrendingUp className="h-4 w-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">94.2%</div>
              <p className="text-xs text-success">+2.1% từ tuần trước</p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mb-8"
      >
        <Card className="shadow-card">
          <CardHeader>
            <CardTitle>Quản lý Nhanh</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Link to="/admin/users">
                <Button className="w-full h-20 flex flex-col gap-2" variant="outline">
                  <UserPlus className="h-6 w-6" />
                  <span>Quản lý Người dùng</span>
                </Button>
              </Link>

              <Link to="/admin/approvals">
                <Button className="w-full h-20 flex flex-col gap-2" variant="outline">
                  <BookOpen className="h-6 w-6" />
                  <span>Phê duyệt Khóa học</span>
                </Button>
              </Link>

              <Link to="/admin/reports">
                <Button className="w-full h-20 flex flex-col gap-2" variant="outline">
                  <FileText className="h-6 w-6" />
                  <span>Báo cáo Thống kê</span>
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Recent Activities & Pending Requests */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.6 }}
        >
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle>Yêu cầu chờ xử lý</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg bg-warning/10 border border-warning/20">
                  <div>
                    <h3 className="font-medium">20 yêu cầu đổi mật khẩu</h3>
                    <p className="text-sm text-muted-foreground">Cần xử lý trong ngày</p>
                  </div>
                  <Button size="sm">Xử lý</Button>
                </div>

                <Link to="/admin/approvals">
                  <div className="flex items-center justify-between p-4 rounded-lg bg-primary/10 border border-primary/20 cursor-pointer hover:bg-primary/15 transition-colors">
                    <div>
                      <h3 className="font-medium">Yêu cầu phê duyệt khóa học</h3>
                      <p className="text-sm text-muted-foreground">Từ giảng viên</p>
                    </div>
                    <Button size="sm">Xem</Button>
                  </div>
                </Link>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.7 }}
        >
          <Card className="shadow-card">
            <CardHeader>
              <CardTitle>Hoạt động Gần đây</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center gap-3 text-sm">
                  <div className="h-2 w-2 rounded-full bg-success"></div>
                  <p className="text-muted-foreground">
                    <span className="font-medium text-foreground">Admin</span> đã thêm 15 sinh viên mới
                  </p>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <div className="h-2 w-2 rounded-full bg-primary"></div>
                  <p className="text-muted-foreground">
                    <span className="font-medium text-foreground">Giảng viên Nguyễn A</span> tạo khóa học mới
                  </p>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <div className="h-2 w-2 rounded-full bg-warning"></div>
                  <p className="text-muted-foreground">
                    <span className="font-medium text-foreground">Hệ thống</span> đã sao lưu dữ liệu
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
};
