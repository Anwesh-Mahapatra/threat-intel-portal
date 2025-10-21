from sqlalchemy import Column, Integer, BigInteger, Text, Boolean, ForeignKey, TIMESTAMP, JSON, LargeBinary
from sqlalchemy.orm import relationship
from .db import Base

class Source(Base):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    kind = Column(Text)   # rss/json/github
    endpoint = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True)
    auth_secret = Column(Text)
    poll_interval_seconds = Column(Integer, default=900)
    last_etag = Column(Text)
    last_modified = Column(TIMESTAMP)

class Item(Base):
    __tablename__ = "items"
    id = Column(BigInteger, primary_key=True)
    source_id = Column(Integer, ForeignKey("sources.id"))
    canonical_url = Column(Text)
    title = Column(Text)
    published_at = Column(TIMESTAMP)
    fetched_at = Column(TIMESTAMP)
    author = Column(Text)
    raw = Column(JSON)
    text = Column(Text)
    hash_sha256 = Column(LargeBinary)
    summary_short = Column(Text)
    lang = Column(Text, default="en")

    source = relationship("Source")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True)

class Technique(Base):
    __tablename__ = "techniques"
    id = Column(Integer, primary_key=True)
    attack_id = Column(Text, unique=True)
    tactic = Column(Text)
    name = Column(Text)

class ItemTag(Base):
    __tablename__ = "item_tags"
    item_id = Column(BigInteger, ForeignKey("items.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)

class ItemTechnique(Base):
    __tablename__ = "item_techniques"
    item_id = Column(BigInteger, ForeignKey("items.id"), primary_key=True)
    technique_id = Column(Integer, ForeignKey("techniques.id"), primary_key=True)

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(BigInteger, primary_key=True)
    item_id = Column(BigInteger, ForeignKey("items.id"))
    type = Column(Text)  # ip/domain/url/sha256/sha1/md5/email
    value = Column(Text)
    context = Column(JSON)
