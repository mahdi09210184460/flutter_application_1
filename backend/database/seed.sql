INSERT INTO categories (id, name) VALUES
  (gen_random_uuid(), 'سکه'),
  (gen_random_uuid(), 'شمش'),
  (gen_random_uuid(), 'زیورآلات');

-- Create users through the registration endpoint so passwords are always bcrypt-hashed.
-- Add an admin by inserting the same user id into admin_users after registration.
