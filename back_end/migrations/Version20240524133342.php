<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20240524133342 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE partie_patron (id INT AUTO_INCREMENT NOT NULL, id_patron_id INT NOT NULL, name VARCHAR(255) NOT NULL, INDEX IDX_B6FA37318D88EF05 (id_patron_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE patron (id INT AUTO_INCREMENT NOT NULL, name VARCHAR(255) NOT NULL, description VARCHAR(255) NOT NULL, PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE user_partie_patron (id INT AUTO_INCREMENT NOT NULL, user_id INT NOT NULL, id_partie_patron_id INT NOT NULL, mailles INT NOT NULL, rangs INT NOT NULL, INDEX IDX_58749A61A76ED395 (user_id), INDEX IDX_58749A616D0DA4C6 (id_partie_patron_id), PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('ALTER TABLE partie_patron ADD CONSTRAINT FK_B6FA37318D88EF05 FOREIGN KEY (id_patron_id) REFERENCES patron (id)');
        $this->addSql('ALTER TABLE user_partie_patron ADD CONSTRAINT FK_58749A61A76ED395 FOREIGN KEY (user_id) REFERENCES user (id)');
        $this->addSql('ALTER TABLE user_partie_patron ADD CONSTRAINT FK_58749A616D0DA4C6 FOREIGN KEY (id_partie_patron_id) REFERENCES partie_patron (id)');
        $this->addSql('DROP TABLE produit');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE produit (id INT AUTO_INCREMENT NOT NULL, name VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL COLLATE `utf8mb4_unicode_ci`, descirption VARCHAR(255) CHARACTER SET utf8mb4 DEFAULT NULL COLLATE `utf8mb4_unicode_ci`, PRIMARY KEY(id)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB COMMENT = \'\' ');
        $this->addSql('ALTER TABLE partie_patron DROP FOREIGN KEY FK_B6FA37318D88EF05');
        $this->addSql('ALTER TABLE user_partie_patron DROP FOREIGN KEY FK_58749A61A76ED395');
        $this->addSql('ALTER TABLE user_partie_patron DROP FOREIGN KEY FK_58749A616D0DA4C6');
        $this->addSql('DROP TABLE partie_patron');
        $this->addSql('DROP TABLE patron');
        $this->addSql('DROP TABLE user_partie_patron');
    }
}
